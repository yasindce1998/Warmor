//go:build ignore

#include "warmor_lsm.h"

// Content-based exec integrity. Every binary (or script) the kernel is about
// to execute is hashed with IMA's SHA-256 and checked against an allowlist of
// known-good digests, so a binary that was tampered with, dropped into the
// container after start, or executed from a memfd is refused no matter what
// path it lives at. This complements lsm_exec, which matches on filename.
//
// The program is sleepable (lsm.s) because bpf_ima_file_hash may read the
// whole file. Hashing every exec would be expensive, so a per-inode verdict is
// cached in inode storage and invalidated when the file changes (ctime/size)
// or when userspace swaps the allowlist (generation bump).

#define SHA256_DIGEST_SIZE 32
// enum hash_algo in include/uapi/linux/hash_info.h
#define WARMOR_HASH_ALGO_SHA256 4

#define INTEGRITY_MODE_OFF     0
#define INTEGRITY_MODE_AUDIT   1
#define INTEGRITY_MODE_ENFORCE 2

#define VERDICT_ALLOWED 1
#define VERDICT_DENIED  2

#define INTEGRITY_STAT_CACHE_HIT  0
#define INTEGRITY_STAT_HASHED     1
#define INTEGRITY_STAT_DENIED     2
#define INTEGRITY_STAT_HASH_ERROR 3
// Not a counter: the last value bpf_ima_file_hash returned (an enum
// hash_algo, or a negative errno), so a fail-closed deny caused by IMA
// using another default hash can be diagnosed.
#define INTEGRITY_STAT_LAST_ALGO  4

struct digest_key {
	__u8 digest[SHA256_DIGEST_SIZE];
};

// Known-good SHA-256 digests (value is unused; presence means allowed).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct digest_key);
	__type(value, __u8);
} integrity_allow SEC(".maps");

struct integrity_config {
	__u32 mode;       // INTEGRITY_MODE_*
	__u32 generation; // bumped by userspace whenever integrity_allow changes
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct integrity_config);
} integrity_cfg SEC(".maps");

struct inode_verdict {
	__s64 ctime_sec;
	__s64 ctime_nsec;
	__s64 size;
	__u32 generation;
	__u32 verdict; // VERDICT_*
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct inode_verdict);
} integrity_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 5);
	__type(key, __u32);
	__type(value, __u64);
} integrity_stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&integrity_stats, &idx);
	if (v)
		*v += 1;
}

// The inode ctime field has moved around: struct timespec64 i_ctime before
// 6.6, __i_ctime in 6.6-6.10, and split i_ctime_sec/i_ctime_nsec since 6.11.
struct inode___ctime_split {
	time64_t i_ctime_sec;
	u32 i_ctime_nsec;
} __attribute__((preserve_access_index));

struct inode___ctime_ts {
	struct timespec64 __i_ctime;
} __attribute__((preserve_access_index));

struct inode___ctime_old {
	struct timespec64 i_ctime;
} __attribute__((preserve_access_index));

static __always_inline void read_ctime(struct inode *inode, __s64 *sec, __s64 *nsec)
{
	if (bpf_core_field_exists(((struct inode___ctime_split *)inode)->i_ctime_sec)) {
		*sec = BPF_CORE_READ((struct inode___ctime_split *)inode, i_ctime_sec);
		*nsec = BPF_CORE_READ((struct inode___ctime_split *)inode, i_ctime_nsec);
	} else if (bpf_core_field_exists(((struct inode___ctime_ts *)inode)->__i_ctime)) {
		*sec = BPF_CORE_READ((struct inode___ctime_ts *)inode, __i_ctime.tv_sec);
		*nsec = BPF_CORE_READ((struct inode___ctime_ts *)inode, __i_ctime.tv_nsec);
	} else {
		*sec = BPF_CORE_READ((struct inode___ctime_old *)inode, i_ctime.tv_sec);
		*nsec = BPF_CORE_READ((struct inode___ctime_old *)inode, i_ctime.tv_nsec);
	}
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(lsm_integrity_check, struct linux_binprm *bprm, int ret)
{
	if (ret != 0)
		return ret;

	__u32 zero = 0;
	struct integrity_config *cfg = bpf_map_lookup_elem(&integrity_cfg, &zero);
	if (!cfg || cfg->mode == INTEGRITY_MODE_OFF)
		return 0;
	__u32 mode = cfg->mode;
	__u32 gen = cfg->generation;

	__u64 cgid = bpf_get_current_cgroup_id();
	if (should_skip_cgroup(cgid))
		return 0;

	struct file *file = bprm->file;
	if (!file)
		return 0;
	struct inode *inode = file->f_inode;
	if (!inode)
		return 0;

	__s64 csec = 0, cnsec = 0;
	read_ctime(inode, &csec, &cnsec);
	__s64 size = inode->i_size;

	struct inode_verdict *cached = bpf_inode_storage_get(&integrity_cache, inode, 0,
							     BPF_LOCAL_STORAGE_GET_F_CREATE);
	__u32 verdict;
	if (cached && cached->verdict != 0 && cached->generation == gen &&
	    cached->ctime_sec == csec && cached->ctime_nsec == cnsec &&
	    cached->size == size) {
		verdict = cached->verdict;
		bump_stat(INTEGRITY_STAT_CACHE_HIT);
	} else {
		struct digest_key key = {};
		long algo = bpf_ima_file_hash(file, key.digest, sizeof(key.digest));
		__u32 last = INTEGRITY_STAT_LAST_ALGO;
		__u64 *lastv = bpf_map_lookup_elem(&integrity_stats, &last);
		if (lastv)
			*lastv = (__u64)algo;
		if (algo != WARMOR_HASH_ALGO_SHA256) {
			// No usable digest (read error, or IMA configured with another
			// default hash). Fail closed: an unverifiable binary is not
			// allowed. Not cached, so a transient failure is retried.
			bump_stat(INTEGRITY_STAT_HASH_ERROR);
			verdict = VERDICT_DENIED;
		} else {
			bump_stat(INTEGRITY_STAT_HASHED);
			verdict = bpf_map_lookup_elem(&integrity_allow, &key) ?
				  VERDICT_ALLOWED : VERDICT_DENIED;
			if (cached) {
				cached->ctime_sec = csec;
				cached->ctime_nsec = cnsec;
				cached->size = size;
				cached->generation = gen;
				cached->verdict = verdict;
			}
		}
	}

	if (verdict == VERDICT_ALLOWED)
		return 0;

	bump_stat(INTEGRITY_STAT_DENIED);
	emit_lsm_event(EVENT_TYPE_INTEGRITY, mode == INTEGRITY_MODE_ENFORCE ? 1 : 0,
		       BPF_CORE_READ(bprm, filename), 1, cgid, 0, 0, 0, 0);

	if (mode == INTEGRITY_MODE_ENFORCE)
		return -1; // -EPERM
	return 0;
}

// Force BTF emission for bpf2go -type.
const struct digest_key *unused_digest_key __attribute__((unused));
const struct integrity_config *unused_integrity_config __attribute__((unused));

char LICENSE[] SEC("license") = "GPL";
