//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/socket_connect")
int BPF_PROG(lsm_connect_check, struct socket *sock, struct sockaddr *address, int addrlen)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	// Check cgroup filter
	if (should_skip_cgroup(cgid))
		return 0;

	// Read address family
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
	} else if (family == 1) { // AF_UNIX
		// Report connects to watched paths only (see unix_watch). Never
		// blocked here: unix sockets have no policy-map rules.
		char path[108] = {};
		int len = bpf_probe_read_kernel_str(path, sizeof(path),
						    ((struct sockaddr_un *)address)->sun_path);
		// len == sizeof(path) means a possibly truncated path; abstract
		// sockets (leading NUL) read as empty. Neither can be watched.
		if (len <= 1 || len >= (int)sizeof(path))
			return 0;
		__u32 path_hash = fnv1a_hash(path, len);
		if (bpf_map_lookup_elem(&unix_watch, &path_hash))
			emit_lsm_event(EVENT_TYPE_NETWORK, 0, path, len, cgid, family, 0, 0, 0);
		return 0;
	} else {
		// Unsupported address family — allow
		return 0;
	}

	struct policy_snapshot snapshot = snapshot_policy(cgid, EVENT_TYPE_NETWORK);
	// Lookup policy: cgroup-specific first
	struct policy_key key = {
		.cgroup_id = cgid,
		.event_type = EVENT_TYPE_NETWORK,
	};
	endpoint_key(&key, family, port, addr_v4, addr_v6);

	struct policy_value *val = lookup_policy(&snapshot, &key);

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			__u8 blocked = is_enforce_enabled() && !val->audit;
			emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_NETWORK, blocked, 0, 0,
				cgid, family, port, addr_v4, addr_v6);

			// An audit-flagged deny is a would-be denial: log it, never block.
			if (blocked)
				return -1; // -EPERM
			return 0;
		}

		if (val->audit) {
			emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_NETWORK, 0, 0, 0,
				cgid, family, port, addr_v4, addr_v6);
		}
		return 0;
	}

	// No match. If userspace marked connect a default-deny domain, this
	// endpoint is not on the allowlist: refuse it (enforce) or record the
	// would-deny (audit). Only AF_INET/AF_INET6 reach here; other families
	// returned before the lookup and stay allowed.
	__u8 dd = lookup_default_deny(&snapshot, cgid, EVENT_TYPE_NETWORK);
	if (dd == DEFAULT_DENY_MODE_DENY) {
		// The verdict is known, so a full ring cannot soften it.
		if (is_enforce_enabled()) {
			emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_NETWORK, 1, 0, 0,
				cgid, family, port, addr_v4, addr_v6);
			return -1; // -EPERM
		}
	} else if (dd == DEFAULT_DENY_MODE_AUDIT) {
		// Fall through to the miss emit below: userspace re-evaluates the
		// event through WASM (which denies) and records the would-deny.
	}

	// No match — emit for userspace evaluation. If the ring is full nobody
	// will evaluate it; --on-event-loss decides.
	if (!emit_lsm_event_generation(snapshot.generation, EVENT_TYPE_NETWORK, 0, 0, 0, cgid, family, port, addr_v4, addr_v6))
		return lost_verdict();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
