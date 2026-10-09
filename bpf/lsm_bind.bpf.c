//go:build ignore

#include "warmor_lsm.h"

static __always_inline __u32 hash_ipv4_endpoint(__u32 addr, __u16 port)
{
	__u32 hash = 2166136261u;
	hash ^= (addr & 0xFF); hash *= 16777619u;
	hash ^= ((addr >> 8) & 0xFF); hash *= 16777619u;
	hash ^= ((addr >> 16) & 0xFF); hash *= 16777619u;
	hash ^= ((addr >> 24) & 0xFF); hash *= 16777619u;
	hash ^= (port & 0xFF); hash *= 16777619u;
	hash ^= ((port >> 8) & 0xFF); hash *= 16777619u;
	return hash;
}

static __always_inline __u32 hash_ipv6_endpoint(const __u8 *addr, __u16 port)
{
	__u32 hash = 2166136261u;
	for (int i = 0; i < 16; i++) {
		hash ^= (__u32)addr[i];
		hash *= 16777619u;
	}
	hash ^= (port & 0xFF); hash *= 16777619u;
	hash ^= ((port >> 8) & 0xFF); hash *= 16777619u;
	return hash;
}

SEC("lsm/socket_bind")
int BPF_PROG(lsm_bind_check, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	if (should_skip_cgroup(cgid))
		return 0;

	__u16 family = 0;
	bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

	__u32 hash = 0;
	__u16 port = 0;
	__u32 addr_v4 = 0;
	__u8 addr_v6[16] = {};

	if (family == 2) { // AF_INET
		struct sockaddr_in {
			__u16 sin_family;
			__u16 sin_port;
			__u32 sin_addr;
		} sin;
		bpf_probe_read_kernel(&sin, sizeof(sin), address);
		port = sin.sin_port;
		addr_v4 = sin.sin_addr;
		hash = hash_ipv4_endpoint(addr_v4, port);
	} else if (family == 10) { // AF_INET6
		struct sockaddr_in6 {
			__u16 sin6_family;
			__u16 sin6_port;
			__u32 sin6_flowinfo;
			__u8  sin6_addr[16];
		} sin6;
		bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
		port = sin6.sin6_port;
		__builtin_memcpy(addr_v6, sin6.sin6_addr, 16);
		hash = hash_ipv6_endpoint(addr_v6, port);
	} else {
		return 0;
	}

	struct policy_key key = {
		.cgroup_id = cgid,
		.rule_hash = hash,
		.event_type = EVENT_TYPE_BIND,
	};

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
