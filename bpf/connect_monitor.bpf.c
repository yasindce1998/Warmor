// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tracepoint_defs.h"
#include "warmor_common.h"

#define AF_INET  2
#define AF_INET6 10

struct sockaddr {
	unsigned short sa_family;
	char sa_data[14];
};

struct in_addr {
	__u32 s_addr;
};

struct sockaddr_in {
	unsigned short sin_family;
	__u16 sin_port;
	struct in_addr sin_addr;
	char sin_zero[8];
};

struct in6_addr {
	__u8 s6_addr[16];
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__u16 sin6_port;
	__u32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

// Event structure matching Go NetworkEvent
struct network_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char comm[16];
	__u16 family;        // AF_INET or AF_INET6
	__u16 remote_port;
	__u32 remote_addr_v4;
	__u8 remote_addr_v6[16];
	__u64 timestamp;
	__u64 cgroup_id;
};

// Ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

// Cgroup filter map: if non-empty, only emit events from listed cgroup IDs
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} cgroup_filter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter* ctx)
{
	struct network_event *event;
	struct sockaddr *addr;
	__u64 cgid = bpf_get_current_cgroup_id();

	// If cgroup filter map has entries, drop events not in the filter
	__u8 *val = bpf_map_lookup_elem(&cgroup_filter, &cgid);
	if (!val) {
		__u64 sentinel = 0;
		__u8 *sentinel_val = bpf_map_lookup_elem(&cgroup_filter, &sentinel);
		if (sentinel_val) {
			return 0;
		}
	}

	// Reserve space
	event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
	if (!event) {
		count_tracepoint_drop();
		return 0;
	}

	// Get process info
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event->pid = pid_tgid >> 32;

	__u64 uid_gid = bpf_get_current_uid_gid();
	event->uid = uid_gid & 0xFFFFFFFF;
	event->gid = uid_gid >> 32;

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	addr = (struct sockaddr *)ctx->args[1];

	// Read address family
	__u16 family;
	bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
	event->family = family;

	if (family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		bpf_probe_read_user(&event->remote_port, sizeof(event->remote_port),
						   &addr_in->sin_port);
		bpf_probe_read_user(&event->remote_addr_v4, sizeof(event->remote_addr_v4),
						   &addr_in->sin_addr);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		bpf_probe_read_user(&event->remote_port, sizeof(event->remote_port),
						   &addr_in6->sin6_port);
		bpf_probe_read_user(&event->remote_addr_v6, sizeof(event->remote_addr_v6),
						   &addr_in6->sin6_addr);
	}

	event->timestamp = bpf_ktime_get_ns();
	event->cgroup_id = cgid;

	// Submit event
	bpf_ringbuf_submit(event, 0);

	return 0;
}

// Force BTF type emission for bpf2go -type flag
const struct network_event *unused_network_event __attribute__((unused));

char LICENSE[] SEC("license") = "GPL";
