//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracepoint_defs.h"

// Minimal CO-RE view of the parent chain; the ___warmor suffix is dropped
// when relocating against kernel BTF (same pattern as lsm_ptrace.bpf.c).
struct task_struct___warmor {
	__s32 tgid;
	char comm[16];
	struct task_struct___warmor *real_parent;
} __attribute__((preserve_access_index));

#define ARGS_MAX  16
#define ARG_LEN   64

// Event structure sent to userspace
struct execve_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char comm[16];          // Process name
	char filename[256];     // Executable path
	__u64 timestamp;
	__u64 cgroup_id;
	__u32 ppid;                 // real_parent's tgid (0 when unreadable)
	char parent_comm[16];       // real_parent's comm ("" when unreadable)
	char args[ARGS_MAX][ARG_LEN]; // argv, NUL-padded; all-zero = none captured
};

// Ring buffer for sending events to userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Cgroup filter map: if non-empty, only emit events from listed cgroup IDs
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} cgroup_filter SEC(".maps");

// Tracepoint for sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	struct execve_event *event;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u64 cgid = bpf_get_current_cgroup_id();

	// If cgroup filter map has entries, drop events not in the filter
	__u8 *val = bpf_map_lookup_elem(&cgroup_filter, &cgid);
	if (!val) {
		// Check if map is non-empty by looking at a sentinel key (0)
		__u64 sentinel = 0;
		__u8 *sentinel_val = bpf_map_lookup_elem(&cgroup_filter, &sentinel);
		if (sentinel_val) {
			// Map is active (has sentinel), and this cgroup is not in it — drop
			return 0;
		}
	}

	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	// Fill event data
	event->pid = pid;
	event->uid = (__u32)uid_gid;
	event->gid = uid_gid >> 32;
	event->timestamp = bpf_ktime_get_ns();
	event->cgroup_id = cgid;

	// Get process name
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// Get filename from syscall arguments
	const char *filename_ptr = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename_ptr);

	// Parent context: real_parent's PID and comm. The ringbuf reservation
	// zeroed the event, so on any read failure ppid stays 0 and parent_comm
	// stays "" — userspace treats both as "unknown".
	struct task_struct___warmor *parent =
		BPF_CORE_READ((struct task_struct___warmor *)bpf_get_current_task(), real_parent);
	if (parent) {
		__s32 ppid = BPF_CORE_READ(parent, tgid);
		event->ppid = ppid > 0 ? (__u32)ppid : 0;
		BPF_CORE_READ_STR_INTO(&event->parent_comm, parent, comm);
	}

	// Walk the syscall's argv (ctx->args[1]). The loop is bounded and stops
	// at the first NULL pointer or unreadable entry; the ringbuf reservation
	// zeroed args, so the remainder reads as "not captured". A longer
	// argument is truncated to ARG_LEN-1 bytes.
	const char **argv = (const char **)ctx->args[1];
	if (argv) {
		for (int i = 0; i < ARGS_MAX; i++) {
			const char *argp;
			if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0)
				break;
			if (!argp)
				break;
			if (bpf_probe_read_user_str(&event->args[i], ARG_LEN, argp) < 0)
				break;
		}
	}

	// Submit event to userspace
	bpf_ringbuf_submit(event, 0);

	return 0;
}

// Force BTF type emission for bpf2go -type flag
const struct execve_event *unused_execve_event __attribute__((unused));

char LICENSE[] SEC("license") = "GPL";
