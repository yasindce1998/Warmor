// SPDX-License-Identifier: GPL-2.0
#ifndef __WARMOR_COMMON_H
#define __WARMOR_COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Per-CPU count of ring-buffer reservation failures in the tracepoint
// monitors. A dropped event is an observation nobody can make, so it must
// never be silent: userspace polls this map and publishes the totals as
// warmor_tracepoint_events_dropped_total{hook}. One slot per monitor; the
// loader reads each object's own map and labels it with that object's hook.
#define TRACEPOINT_DROP_RESERVE 0
#define TRACEPOINT_DROPS_MAX    1

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, TRACEPOINT_DROPS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} tracepoint_drops SEC(".maps");

static __always_inline void count_tracepoint_drop(void)
{
	__u32 idx = TRACEPOINT_DROP_RESERVE;
	__u64 *n = bpf_map_lookup_elem(&tracepoint_drops, &idx);
	if (n)
		*n += 1;
}

#endif /* __WARMOR_COMMON_H */
