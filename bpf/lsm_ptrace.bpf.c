//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_check, struct task_struct *child, unsigned int mode)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	if (should_skip_cgroup(cgid))
		return 0;

	// comm is a char[16] field, not a pointer: BPF_CORE_READ would copy the
	// array into a temp and hand back a pointer to that stack copy. Use the
	// purpose-built string reader, which relocates the field offset and reads
	// the NUL-terminated string directly into comm_buf.
	char comm_buf[16];
	BPF_CORE_READ_STR_INTO(&comm_buf, child, comm);

	__u32 hash = fnv1a_hash(comm_buf, 16);

	struct policy_key key = {
		.cgroup_id = cgid,
		.rule_hash = hash,
		.event_type = EVENT_TYPE_PTRACE,
	};

	struct policy_value *val = bpf_map_lookup_elem(&policy_map, &key);
	if (!val) {
		key.cgroup_id = 0;
		val = bpf_map_lookup_elem(&policy_map, &key);
	}

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			emit_lsm_event(EVENT_TYPE_PTRACE, 1, comm_buf, 16,
				cgid, 0, 0, 0, 0);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (is_enforce_enabled() && !val->audit)
				return -1;
			return 0;
		}

		if (val->audit) {
			emit_lsm_event(EVENT_TYPE_PTRACE, 0, comm_buf, 16,
				cgid, 0, 0, 0, 0);
		}
		return 0;
	}

	emit_lsm_event(EVENT_TYPE_PTRACE, 0, comm_buf, 16, cgid, 0, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
