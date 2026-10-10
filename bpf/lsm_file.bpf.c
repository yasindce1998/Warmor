//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/file_open")
int BPF_PROG(lsm_file_check, struct file *file)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	// Check cgroup filter
	if (should_skip_cgroup(cgid))
		return 0;

	// Read the file path from dentry — use nested BPF_CORE_READ to get
	// the name pointer directly, avoiding struct qstr layout mismatch.
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return 0;

	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	if (!name)
		return 0;

	char fname_buf[64];
	int len = bpf_probe_read_kernel_str(fname_buf, sizeof(fname_buf), name);
	if (len <= 0)
		return 0;

	// Hash for policy map lookup. This is the dentry basename, not the full
	// path, so userspace deliberately does not compile file decisions into
	// policy_map (a basename rule would apply to every same-named file).
	__u32 hash = fnv1a_hash(fname_buf, len);

	// Lookup policy: cgroup-specific first
	struct policy_key key = {
		.cgroup_id = cgid,
		.rule_hash = hash,
		.event_type = EVENT_TYPE_FILE,
	};

	struct policy_value *val = bpf_map_lookup_elem(&policy_map, &key);
	if (!val) {
		// Try global rule
		key.cgroup_id = 0;
		val = bpf_map_lookup_elem(&policy_map, &key);
	}

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			emit_lsm_event(EVENT_TYPE_FILE, 1, fname_buf, len,
				cgid, 0, 0, 0, 0);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (is_enforce_enabled() && !val->audit)
				return -1; // -EPERM
			return 0;
		}

		if (val->audit) {
			emit_lsm_event(EVENT_TYPE_FILE, 0, fname_buf, len,
				cgid, 0, 0, 0, 0);
		}
		return 0;
	}

	// No match — emit for userspace WASM evaluation
	emit_lsm_event(EVENT_TYPE_FILE, 0, fname_buf, len, cgid, 0, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
