//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/socket_listen")
int BPF_PROG(lsm_listen_check, struct socket *sock, int backlog)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	if (should_skip_cgroup(cgid))
		return 0;

	__u16 port = BPF_CORE_READ(sock, sk, __sk_common.skc_num);
	if (port == 0)
		return 0;

	__u16 family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);

	struct policy_snapshot snapshot = snapshot_policy(cgid, EVENT_TYPE_LISTEN);
	struct policy_key key = {
		.cgroup_id = cgid,
		.event_type = EVENT_TYPE_LISTEN,
		.family = family,
	};
	key.port[0] = port >> 8;
	key.port[1] = port & 255;

	struct policy_value *val = lookup_policy(&snapshot, &key);

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			__u8 blocked = is_enforce_enabled() && !val->audit;
			emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_LISTEN, blocked, 0, 0,
				cgid, family, port, 0, 0);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (blocked)
				return -1;
			return 0;
		}

		if (val->audit) {
			emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_LISTEN, 0, 0, 0,
				cgid, family, port, 0, 0);
		}
		return 0;
	}

	emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_LISTEN, 0, 0, 0, cgid, family, port, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
