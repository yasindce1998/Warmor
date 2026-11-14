//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/socket_bind")
int BPF_PROG(lsm_bind_check, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	if (should_skip_cgroup(cgid))
		return 0;

	__u16 family = 0;
	if (addrlen < 2 || bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family))
		return 0;

	__u16 port = 0;
	__u32 addr_v4 = 0;
	__u8 addr_v6[16] = {};

	if (family == 2) { // AF_INET
		struct sockaddr_in {
			__u16 sin_family;
			__u16 sin_port;
			__u32 sin_addr;
		} sin;
		if (addrlen < 16 || bpf_probe_read_kernel(&sin, sizeof(sin), address))
			return 0;
		port = sin.sin_port;
		addr_v4 = sin.sin_addr;
	} else if (family == 10) { // AF_INET6
		struct sockaddr_in6 {
			__u16 sin6_family;
			__u16 sin6_port;
			__u32 sin6_flowinfo;
			__u8  sin6_addr[16];
		} sin6;
		// The RFC2133 form is 24 bytes (no scope_id) and is still valid.
		if (addrlen < (int)sizeof(sin6) || bpf_probe_read_kernel(&sin6, sizeof(sin6), address))
			return 0;
		port = sin6.sin6_port;
		__builtin_memcpy(addr_v6, sin6.sin6_addr, 16);
	} else {
		return 0;
	}

	struct policy_key key = {
		.cgroup_id = cgid,
		.event_type = EVENT_TYPE_BIND,
	};
	endpoint_key(&key, family, port, addr_v4, addr_v6);

	struct policy_value *val = bpf_map_lookup_elem(&policy_map, &key);
	if (!val) {
		key.cgroup_id = 0;
		val = bpf_map_lookup_elem(&policy_map, &key);
	}

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			emit_lsm_event(EVENT_TYPE_BIND, 1, 0, 0,
				cgid, family, port, addr_v4, addr_v6);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (is_enforce_enabled() && !val->audit)
				return -1;
			return 0;
		}

		if (val->audit) {
			emit_lsm_event(EVENT_TYPE_BIND, 0, 0, 0,
				cgid, family, port, addr_v4, addr_v6);
		}
		return 0;
	}

	emit_lsm_event(EVENT_TYPE_BIND, 0, 0, 0, cgid, family, port, addr_v4, addr_v6);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
