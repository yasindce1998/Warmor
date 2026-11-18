//go:build ignore

#include "warmor_lsm.h"

// Minimal CO-RE views of the cgroup chain (task->cgroups->dfl_cgrp->kn->id);
// the ___warmor suffix is dropped when relocating against kernel BTF.
struct kernfs_node___warmor {
	__u64 id;
} __attribute__((preserve_access_index));

struct cgroup___warmor {
	struct kernfs_node___warmor *kn;
} __attribute__((preserve_access_index));

struct css_set___warmor {
	struct cgroup___warmor *dfl_cgrp;
} __attribute__((preserve_access_index));

struct task_struct___warmor {
	struct css_set___warmor *cgroups;
} __attribute__((preserve_access_index));

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
	char comm_buf[16] = {};
	int len = BPF_CORE_READ_STR_INTO(&comm_buf, child, comm);
	if (len <= 0)
		return 0;

	// The target's cgroup (its kernfs node id, the same id
	// bpf_get_current_cgroup_id returns), so userspace can tell a ptrace
	// inside one container from one that reaches across a boundary.
	__u64 target_cgid = BPF_CORE_READ((struct task_struct___warmor *)child, cgroups, dfl_cgrp, kn, id);

	struct policy_snapshot snapshot = snapshot_policy(cgid, EVENT_TYPE_PTRACE);

	// The exact key identifies the TARGET of the ptrace, not the tracer:
	// cgroup_id is the target's cgroup (previously available only in the
	// event's aux_id) and path carries the target's comm. A DENY userspace
	// writes under this key therefore cannot affect a same-named target in a
	// different container. A policy-map miss still falls back to the global
	// (cgroup_id = 0) key, so static comm-only SetRule entries keep matching.
	struct policy_key key = {
		.cgroup_id = target_cgid,
		.event_type = EVENT_TYPE_PTRACE,
	};
	__builtin_memcpy(key.path, comm_buf, sizeof(comm_buf));

	struct policy_value *val = lookup_policy(&snapshot, &key);

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			__u8 blocked = is_enforce_enabled() && !val->audit;
			emit_lsm_event_aux_generation(snapshot.generation, EVENT_TYPE_PTRACE, blocked, comm_buf, 16,
				cgid, 0, 0, 0, 0, 0, target_cgid);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (blocked)
				return -1;
			return 0;
		}

		if (val->audit) {
			emit_lsm_event_aux_generation(snapshot.generation, EVENT_TYPE_PTRACE, 0, comm_buf, 16,
				cgid, 0, 0, 0, 0, 0, target_cgid);
		}
		return 0;
	}

	// No match — emit for userspace evaluation. If the ring is full nobody
	// will evaluate it; --on-event-loss decides (fail closed when configured).
	if (!emit_lsm_event_aux_generation(snapshot.generation, EVENT_TYPE_PTRACE, 0, comm_buf, 16, cgid, 0, 0, 0, 0, 0, target_cgid))
		return lost_verdict(EVENT_TYPE_PTRACE);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
