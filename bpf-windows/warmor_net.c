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

// Requires eBPF-for-Windows >= 1.0. Older releases exposed a context-taking
// helper (ID 0x10000, bpf_sock_addr_get_current_pid_tgid); it was removed in
// 1.0-rc1 in favour of the global, no-argument bpf_get_current_pid_tgid (ID 19),
// which netebpfext implements as (process_id << 32) | thread_id. Calling the
// removed helper compiles against the SDK headers but fails helper binding,
// so the image never attaches and enforcement silently falls back to ETW.

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

    pid = (uint32_t)(bpf_get_current_pid_tgid() >> 32);
    rec.hdr.kind = WARMOR_REC_NETWORK;
    rec.hdr.pid = pid;
    rec.family = family;
    rec.direction = direction;
    rec.protocol = (uint8_t)ctx->protocol;

    // netebpfext fills the WFP fields by hook:
    //   connect (egress)   msg_src_* = local,  user_* = remote
    //   recv_accept        msg_src_* = remote, user_* = local
    //   bind               user_* = local endpoint, msg_src_* = 0
    //   listen             both = local listen endpoint
    // Microsoft's headers and samples disagree on the connect/accept mapping,
    // so keep it in one place and verify on a VM with a non-loopback peer.
    if (direction == WARMOR_DIR_CONNECT) {
        rec.remote_port = ctx->user_port;
        rec.local_port = ctx->msg_src_port;
        if (family == WARMOR_AF_INET) {
            __builtin_memcpy(rec.remote_addr, &ctx->user_ip4, 4);
            __builtin_memcpy(rec.local_addr, &ctx->msg_src_ip4, 4);
        } else {
            __builtin_memcpy(rec.remote_addr, ctx->user_ip6, 16);
            __builtin_memcpy(rec.local_addr, ctx->msg_src_ip6, 16);
        }
    } else if (direction == WARMOR_DIR_ACCEPT) {
        rec.remote_port = ctx->msg_src_port;
        rec.local_port = ctx->user_port;
        if (family == WARMOR_AF_INET) {
            __builtin_memcpy(rec.remote_addr, &ctx->msg_src_ip4, 4);
            __builtin_memcpy(rec.local_addr, &ctx->user_ip4, 4);
        } else {
            __builtin_memcpy(rec.remote_addr, ctx->msg_src_ip6, 16);
            __builtin_memcpy(rec.local_addr, ctx->user_ip6, 16);
        }
    } else {
        // bind / listen: netebpfext reports the local endpoint in user_* (in
        // both fields for listen). Mirror it into remote_* too so the shared
        // key builder and the Linux-style event (local endpoint in
        // RemotePort) stay uniform.
        rec.local_port = ctx->user_port;
        rec.remote_port = ctx->user_port;
        if (family == WARMOR_AF_INET) {
            __builtin_memcpy(rec.local_addr, &ctx->user_ip4, 4);
            __builtin_memcpy(rec.remote_addr, &ctx->user_ip4, 4);
        } else {
            __builtin_memcpy(rec.local_addr, ctx->user_ip6, 16);
            __builtin_memcpy(rec.remote_addr, ctx->user_ip6, 16);
        }
    }

    // Requesting-user identity. Available on all CGROUP_SOCK_ADDR hooks;
    // is_admin is -1 when netebpfext has no token for the request.
    rec.is_admin = bpf_is_current_admin(ctx);
    rec.logon_id = bpf_get_current_logon_id(ctx);
    rec.socket_cookie = bpf_get_socket_cookie(ctx);

    info = bpf_map_lookup_elem(&proc_info, &pid);
    if (info != NULL) {
        rec.image_hash = info->image_hash;
        // Captured at hook time. A record that waits in the ring buffer while
        // its PID is recycled still identifies the process that made the call.
        rec.creation_time = info->creation_time;
    }

    if (rec.image_hash != 0) {
        key.image_hash = rec.image_hash;
        key.family = family;
        key.direction = direction;
        key.protocol = rec.protocol;
        // remote_* holds the peer for connect/accept and the local endpoint
        // for bind/listen, so the same key builder covers all four hooks.
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

// bind/listen attach types were added in eBPF-for-Windows v1.4. They use the
// same CGROUP_SOCK_ADDR program type, so a REJECT verdict is a hard WFP block
// just like connect/accept. netebpfext reports the local endpoint in user_*
// for bind and in both fields for listen (see docs/windows-hardening-plan.md).
SEC("cgroup/bind4")
int
warmor_bind4(bpf_sock_addr_t* ctx)
{
    return warmor_sock_addr(ctx, WARMOR_AF_INET, WARMOR_DIR_BIND);
}

SEC("cgroup/bind6")
int
warmor_bind6(bpf_sock_addr_t* ctx)
{
    return warmor_sock_addr(ctx, WARMOR_AF_INET6, WARMOR_DIR_BIND);
}

SEC("cgroup/listen4")
int
warmor_listen4(bpf_sock_addr_t* ctx)
{
    return warmor_sock_addr(ctx, WARMOR_AF_INET, WARMOR_DIR_LISTEN);
}

SEC("cgroup/listen6")
int
warmor_listen6(bpf_sock_addr_t* ctx)
{
    return warmor_sock_addr(ctx, WARMOR_AF_INET6, WARMOR_DIR_LISTEN);
}
