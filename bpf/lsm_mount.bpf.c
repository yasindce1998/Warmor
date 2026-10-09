//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/sb_mount")
int BPF_PROG(lsm_mount_check, const char *dev_name, const struct path *path,
	const char *type, unsigned long flags, void *data)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	if (should_skip_cgroup(cgid))
		return 0;

	if (!type)
		return 0;

	char type_buf[64];
	int len = bpf_probe_read_kernel_str(type_buf, sizeof(type_buf), type);
	if (len <= 0)
		return 0;

	__u32 hash = fnv1a_hash(type_buf, len);

	struct policy_key key = {
		.cgroup_id = cgid,
		.rule_hash = hash,
		.event_type = EVENT_TYPE_MOUNT,
	};

	// A full buffer means the string may have been truncated, and the hash
	// would then cover only a prefix shared with other strings. Never consult
	// the policy map for it; let userspace evaluate the event instead.
	struct policy_value *val = 0;
	if (len < (int)sizeof(type_buf)) {
		val = bpf_map_lookup_elem(&policy_map, &key);
		if (!val) {
			key.cgroup_id = 0;
			val = bpf_map_lookup_elem(&policy_map, &key);
		}
	}

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			emit_lsm_event(EVENT_TYPE_MOUNT, 1, type_buf, len,
				cgid, 0, 0, 0, 0);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (is_enforce_enabled() && !val->audit)
				return -1;
			return 0;
		}

		if (val->audit) {
			emit_lsm_event(EVENT_TYPE_MOUNT, 0, type_buf, len,
				cgid, 0, 0, 0, 0);
		}
		return 0;
	}

	emit_lsm_event(EVENT_TYPE_MOUNT, 0, type_buf, len, cgid, 0, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
