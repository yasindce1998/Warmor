// SPDX-License-Identifier: MIT
// Copyright (c) 2026 warmor
//
// Network enforcement for eBPF-for-Windows (netebpfext).
//
// The CGROUP_SOCK_ADDR hooks run synchronously in WFP's ALE layers, so a
// REJECT verdict stops the connect/accept before it happens. Every call is
// also reported to userspace, which evaluates it with the WASM policy and
// writes the decision back into net_policy for the next identical attempt.
//
// Rules are keyed on (image, family, direction, protocol, remote addr, port):
// a decision only applies to the same executable talking to the same
// endpoint it was made for.

#include "bpf_helpers.h"
#include "ebpf_nethooks.h"
#include "warmor_efw.h"

// ebpf_nethooks.h assigns the helper ID but does not declare the prototype.
#ifndef bpf_sock_addr_get_current_pid_tgid
EBPF_HELPER(uint64_t, bpf_sock_addr_get_current_pid_tgid, (bpf_sock_addr_t * ctx));
#define bpf_sock_addr_get_current_pid_tgid \
    ((bpf_sock_addr_get_current_pid_tgid_t)BPF_FUNC_sock_addr_get_current_pid_tgid)
#endif

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct warmor_net_key);
    __type(value, struct warmor_policy_value);
    __uint(max_entries, 16384);
} net_policy SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t); // PID
    __type(value, struct warmor_proc_info);
    __uint(max_entries, 65536);
} proc_info SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} net_events SEC(".maps");

static __inline int
warmor_sock_addr(bpf_sock_addr_t* ctx, uint8_t family, uint8_t direction)
{
    struct warmor_net_rec rec;
    struct warmor_net_key key;
    struct warmor_proc_info* info;
    struct warmor_policy_value* rule;
    int verdict = BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    uint32_t pid;

    __builtin_memset(&rec, 0, sizeof(rec));
    __builtin_memset(&key, 0, sizeof(key));

    pid = (uint32_t)(bpf_sock_addr_get_current_pid_tgid(ctx) >> 32);
    rec.hdr.kind = WARMOR_REC_NETWORK;
    rec.hdr.pid = pid;
    rec.family = family;
    rec.direction = direction;
    rec.protocol = (uint8_t)ctx->protocol;
    // For connect and recv_accept alike, user_* is the remote endpoint and
    // msg_src_* the local one.
    rec.remote_port = ctx->user_port;
    rec.local_port = ctx->msg_src_port;
    if (family == WARMOR_AF_INET) {
        __builtin_memcpy(rec.remote_addr, &ctx->user_ip4, 4);
        __builtin_memcpy(rec.local_addr, &ctx->msg_src_ip4, 4);
    } else {
        __builtin_memcpy(rec.remote_addr, ctx->user_ip6, 16);
        __builtin_memcpy(rec.local_addr, ctx->msg_src_ip6, 16);
    }

    info = bpf_map_lookup_elem(&proc_info, &pid);
    if (info != NULL) {
        rec.image_hash = info->image_hash;
    }

    if (rec.image_hash != 0) {
        key.image_hash = rec.image_hash;
        key.family = family;
        key.direction = direction;
        key.protocol = rec.protocol;
        key.port = rec.remote_port;
        __builtin_memcpy(key.addr, rec.remote_addr, 16);

        rule = bpf_map_lookup_elem(&net_policy, &key);
        if (rule != NULL && rule->action == WARMOR_ACTION_DENY) {
            if (rule->audit) {
                rec.hdr.verdict = WARMOR_VERDICT_AUDIT;
            } else {
                rec.hdr.verdict = WARMOR_VERDICT_BLOCKED;
                verdict = BPF_SOCK_ADDR_VERDICT_REJECT;
            }
        }
    }

    // A full ring buffer drops the report, never the verdict.
    bpf_ringbuf_output(&net_events, &rec, sizeof(rec), 0);
    return verdict;
}

SEC("cgroup/connect4")
int
warmor_connect4(bpf_sock_addr_t* ctx)
{
    return warmor_sock_addr(ctx, WARMOR_AF_INET, WARMOR_DIR_CONNECT);
}

SEC("cgroup/connect6")
int
warmor_connect6(bpf_sock_addr_t* ctx)
{
    return warmor_sock_addr(ctx, WARMOR_AF_INET6, WARMOR_DIR_CONNECT);
}

SEC("cgroup/recv_accept4")
int
warmor_recv_accept4(bpf_sock_addr_t* ctx)
{
    return warmor_sock_addr(ctx, WARMOR_AF_INET, WARMOR_DIR_ACCEPT);
}

SEC("cgroup/recv_accept6")
int
warmor_recv_accept6(bpf_sock_addr_t* ctx)
{
    return warmor_sock_addr(ctx, WARMOR_AF_INET6, WARMOR_DIR_ACCEPT);
}
