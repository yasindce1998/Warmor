// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tracepoint_defs.h"
#include "warmor_common.h"

// Event structure matching Go FileEvent
struct file_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char comm[16];
	char path[256];
	__u32 flags;
	__u32 mode;
	__u64 timestamp;
	__u64 cgroup_id;
};

// Ring buffer for sending events to userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

// Cgroup filter map: if non-empty, only emit events from listed cgroup IDs
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} cgroup_filter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	struct file_event *event;
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

	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
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

	bpf_probe_read_user_str(&event->path, sizeof(event->path),
							(void *)ctx->args[1]);
	event->flags = ctx->args[2];
	event->mode = ctx->args[3];
	event->timestamp = bpf_ktime_get_ns();
	event->cgroup_id = cgid;

	// Submit event
	bpf_ringbuf_submit(event, 0);

	return 0;
}

// Force BTF type emission for bpf2go -type flag
const struct file_event *unused_file_event __attribute__((unused));

char LICENSE[] SEC("license") = "GPL";
