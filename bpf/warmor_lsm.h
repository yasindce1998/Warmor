#ifndef __WARMOR_LSM_H
#define __WARMOR_LSM_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_TYPE_EXEC    0
#define EVENT_TYPE_FILE    1
#define EVENT_TYPE_NETWORK 2
#define EVENT_TYPE_BIND    3
#define EVENT_TYPE_LISTEN  4
#define EVENT_TYPE_PTRACE  5
#define EVENT_TYPE_MOUNT   6

#define ACTION_ALLOW 0
#define ACTION_DENY  1

#define POLICY_MAP_MAX_ENTRIES 65536
#define LSM_RINGBUF_SIZE (256 * 1024)

// Policy map key: cgroup + rule hash + event type
struct policy_key {
	__u64 cgroup_id;
	__u32 rule_hash;
	__u8  event_type;
	__u8  pad[3];
};

// Policy map value: action + metadata
struct policy_value {
	__u8  action;     // ACTION_ALLOW or ACTION_DENY
	__u8  audit;      // 1 = log even on allow
	__u16 pad;
	__u32 hit_count;
};

// LSM event sent to userspace for events without a policy map hit
struct warmor_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char  comm[16];
	char  filename[256];
	__u64 timestamp;
	__u64 cgroup_id;
	__u8  event_type;
	__u8  decision;     // 0=miss (needs userspace), 1=denied by map
	__u16 remote_port;
	__u32 remote_addr_v4;
	__u8  remote_addr_v6[16];
	__u16 family;       // AF_INET/AF_INET6 for network events, 0 otherwise
	__u16 pad[3];
};

// Shared policy map — all LSM programs reference the same map via BTF
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, POLICY_MAP_MAX_ENTRIES);
	__type(key, struct policy_key);
	__type(value, struct policy_value);
} policy_map SEC(".maps");

// Ring buffer for events that need userspace evaluation
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, LSM_RINGBUF_SIZE);
} lsm_events SEC(".maps");

// Cgroup filter: if non-empty (sentinel key=0 present), only process listed cgroups
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} lsm_cgroup_filter SEC(".maps");

// LSM enforce toggle: key=0, value=1 means enforce; value=0 means audit-only
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} lsm_enforce SEC(".maps");

// Upper bound on the bytes fnv1a_hash will consume. Matches the largest
// string buffer we hash (and warmor_event.filename), so the hash covers the
// whole string, exactly like userspace HashPattern. Hashing only a prefix
// would let a rule for one string match every string sharing that prefix.
#define WARMOR_HASH_STR_MAX 256

// FNV-1a 32-bit hash of a NUL-terminated string of at most len bytes.
// Bytes are hashed unsigned (char is signed on the BPF target), so the result
// equals Go's hash/fnv New32a over the same bytes. The loop is bounded by a
// constant for the verifier (bounded loops, kernel >= 5.3).
static __always_inline __u32 fnv1a_hash(const char *data, int len)
{
	__u32 hash = 2166136261u;
	for (int i = 0; i < WARMOR_HASH_STR_MAX; i++) {
		if (i >= len || data[i] == 0)
			break;
		hash ^= (__u32)(__u8)data[i];
		hash *= 16777619u;
	}
	return hash;
}

// Check if cgroup filtering is active and this cgroup should be skipped
static __always_inline int should_skip_cgroup(__u64 cgid)
{
	__u8 *val = bpf_map_lookup_elem(&lsm_cgroup_filter, &cgid);
	if (val)
		return 0; // cgroup is in the filter — process it

	__u64 sentinel = 0;
	__u8 *sentinel_val = bpf_map_lookup_elem(&lsm_cgroup_filter, &sentinel);
	if (sentinel_val)
		return 1; // filter is active but cgroup not in it — skip

	return 0; // filter is empty — process all
}

// Check if enforcement is enabled (vs audit-only)
static __always_inline int is_enforce_enabled(void)
{
	__u32 key = 0;
	__u8 *val = bpf_map_lookup_elem(&lsm_enforce, &key);
	if (val && *val == 1)
		return 1;
	return 0;
}

// Emit an LSM event to the ring buffer
static __always_inline void emit_lsm_event(
	__u8 event_type, __u8 decision,
	const char *filename, int filename_len,
	__u64 cgroup_id, __u16 family,
	__u16 remote_port, __u32 remote_addr_v4,
	const __u8 *remote_addr_v6)
{
	struct warmor_event *event;

	event = bpf_ringbuf_reserve(&lsm_events, sizeof(*event), 0);
	if (!event)
		return;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	event->pid = pid_tgid >> 32;
	event->uid = (__u32)uid_gid;
	event->gid = uid_gid >> 32;
	event->timestamp = bpf_ktime_get_ns();
	event->cgroup_id = cgroup_id;
	event->event_type = event_type;
	event->decision = decision;
	event->remote_port = remote_port;
	event->remote_addr_v4 = remote_addr_v4;
	event->family = family;
	__builtin_memset(event->pad, 0, sizeof(event->pad));

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	if (filename && filename_len > 0) {
		bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), filename);
	} else {
		event->filename[0] = 0;
	}

	if (remote_addr_v6) {
		__builtin_memcpy(event->remote_addr_v6, remote_addr_v6, 16);
	} else {
		__builtin_memset(event->remote_addr_v6, 0, 16);
	}

	bpf_ringbuf_submit(event, 0);
}

// Force BTF type emission for bpf2go -type flag
const struct warmor_event *unused_warmor_event __attribute__((unused));
const struct policy_key *unused_policy_key __attribute__((unused));
const struct policy_value *unused_policy_value __attribute__((unused));

#endif /* __WARMOR_LSM_H */
