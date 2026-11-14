//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_exec_check, struct linux_binprm *bprm, int ret)
{
	// If a previous LSM already denied, respect that
	if (ret != 0)
		return ret;

	__u64 cgid = bpf_get_current_cgroup_id();

	// Check cgroup filter
	if (should_skip_cgroup(cgid))
		return 0;
	struct policy_snapshot snapshot = snapshot_policy(cgid, EVENT_TYPE_EXEC);

	// Read the filename being executed (same bound as warmor_event.filename)
	const char *filename = BPF_CORE_READ(bprm, filename);
	// Lookup policy: cgroup-specific rule first
	struct policy_key key = {
		.cgroup_id = cgid,
		.event_type = EVENT_TYPE_EXEC,
	};
	// Read into the zeroed key so the string tail is deterministic, without
	// a second path buffer consuming the verifier's 512-byte stack.
	int len = bpf_probe_read_kernel_str(key.path, sizeof(key.path), filename);

	// Failed and possibly truncated reads are misses, never prefix matches.
	struct policy_value *val = 0;
	if (len > 0 && len < (int)sizeof(key.path)) {
		val = lookup_policy(&snapshot, &key);
	}

	if (val) {
		// Policy map hit — increment counter
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			__u8 blocked = is_enforce_enabled() && !val->audit;
			// Emit audit event for the denial
			emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_EXEC, blocked, key.path, len,
				cgid, 0, 0, 0, 0);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (blocked)
				return -1; // -EPERM
			return 0; // audit-only mode
		}

		// ACTION_ALLOW — if audit flag set, emit event
		if (val->audit) {
			emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_EXEC, 0, key.path, len,
				cgid, 0, 0, 0, 0);
		}
		return 0;
	}

	// No policy map entry. If userspace marked exec a default-deny domain,
	// this path is not on the allowlist: refuse it (enforce) or record the
	// would-deny (audit). This also covers a possibly-truncated filename —
	// an allowlisted path never fills the buffer (exact rules cap at 254
	// bytes), so a truncated name is not provably allowed.
	__u8 dd = lookup_default_deny(&snapshot, cgid, EVENT_TYPE_EXEC);
	if (dd == DEFAULT_DENY_MODE_DENY) {
		// The verdict is known, so a full ring cannot soften it: emit is
		// best effort, the deny stands.
		if (is_enforce_enabled()) {
			emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_EXEC, 1, key.path, len,
				cgid, 0, 0, 0, 0);
			return -1; // -EPERM
		}
	} else if (dd == DEFAULT_DENY_MODE_AUDIT) {
		// Fall through to the miss emit below: userspace re-evaluates the
		// event through WASM (which denies) and records the would-deny.
	}

	// No policy map entry — emit to userspace for WASM evaluation. If the
	// ring is full nobody will evaluate it; --on-event-loss decides.
	if (!emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_EXEC, 0, key.path, len, cgid, 0, 0, 0, 0))
		return lost_verdict();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
