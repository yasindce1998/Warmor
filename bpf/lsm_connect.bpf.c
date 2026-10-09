//go:build ignore

#include "warmor_lsm.h"

// Hash an IPv4 address + port into a rule_hash
static __always_inline __u32 hash_ipv4_endpoint(__u32 addr, __u16 port)
{
	__u32 hash = 2166136261u;
	// Hash the 4 bytes of the address
	hash ^= (addr & 0xFF); hash *= 16777619u;
	hash ^= ((addr >> 8) & 0xFF); hash *= 16777619u;
	hash ^= ((addr >> 16) & 0xFF); hash *= 16777619u;
	hash ^= ((addr >> 24) & 0xFF); hash *= 16777619u;
	// Hash the port (2 bytes)
	hash ^= (port & 0xFF); hash *= 16777619u;
	hash ^= ((port >> 8) & 0xFF); hash *= 16777619u;
	return hash;
}

// Hash an IPv6 address + port into a rule_hash
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

SEC("lsm/socket_connect")
int BPF_PROG(lsm_connect_check, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	// Check cgroup filter
	if (should_skip_cgroup(cgid))
		return 0;

	// Read address family
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
		// Unsupported address family — allow
		return 0;
	}

	// Lookup policy: cgroup-specific first
	struct policy_key key = {
		.cgroup_id = cgid,
		.rule_hash = hash,
		.event_type = EVENT_TYPE_NETWORK,
	};

	struct policy_value *val = bpf_map_lookup_elem(&policy_map, &key);
	if (!val) {
		key.cgroup_id = 0;
		val = bpf_map_lookup_elem(&policy_map, &key);
	}

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			emit_lsm_event(EVENT_TYPE_NETWORK, 1, 0, 0,
				cgid, family, port, addr_v4, addr_v6);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (is_enforce_enabled() && !val->audit)
				return -1; // -EPERM
			return 0;
		}

		if (val->audit) {
			emit_lsm_event(EVENT_TYPE_NETWORK, 0, 0, 0,
				cgid, family, port, addr_v4, addr_v6);
		}
		return 0;
	}

	// No match — emit for userspace evaluation
	emit_lsm_event(EVENT_TYPE_NETWORK, 0, 0, 0, cgid, family, port, addr_v4, addr_v6);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
