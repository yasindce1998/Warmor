// SPDX-License-Identifier: MIT
// Copyright (c) 2026 warmor
//
// Process enforcement for eBPF-for-Windows, using the process hook from
// microsoft/ntosebpfext.
//
// The hook runs during process creation; returning a failure NTSTATUS
// denies it, so a denied image never starts. Creations and exits are
// reported to userspace, which keeps its process table from them and writes
// WASM decisions back into proc_deny.
//
// proc_deny is keyed on the image path hash only: the WASM policy ABI sees
// the image (and comm), not the command line, so that is all a cached
// decision can depend on. Command-line rules are enforced in userspace.

#include "bpf_helpers.h"
#include "ebpf_ntos_hooks.h"
#include "warmor_efw.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint64_t); // image hash
    __type(value, struct warmor_policy_value);
    __uint(max_entries, 16384);
} proc_deny SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint32_t);
    __type(value, struct warmor_proc_rec);
    __uint(max_entries, 1);
} proc_scratch SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} proc_events SEC(".maps");

SEC("process")
int
warmor_process(process_md_t* ctx)
{
    struct warmor_proc_rec* rec;
    struct warmor_policy_value* rule;
    uint32_t zero = 0;
    int status = 0;

    if (ctx->operation == PROCESS_OPERATION_DELETE) {
        struct warmor_proc_exit_rec exit_rec;
        __builtin_memset(&exit_rec, 0, sizeof(exit_rec));
        exit_rec.hdr.kind = WARMOR_REC_PROCESS_EXIT;
        exit_rec.hdr.pid = ctx->process_id;
        exit_rec.exit_code = ctx->process_exit_code;
        bpf_ringbuf_output(&proc_events, &exit_rec, sizeof(exit_rec), 0);
        return 0; // ignored for deletions
    }

    rec = bpf_map_lookup_elem(&proc_scratch, &zero);
    if (rec == NULL) {
        return 0;
    }
    memset(rec, 0, sizeof(*rec));

    rec->hdr.kind = WARMOR_REC_PROCESS_CREATE;
    rec->hdr.pid = ctx->process_id;
    rec->ppid = ctx->parent_process_id;
    rec->creation_time = ctx->creation_time;

    // Leave room for the NUL the hash loop stops at.
    bpf_process_get_image_path(ctx, rec->image, sizeof(rec->image) - 2);
    rec->image_hash = warmor_image_hash(rec->image, &rec->image_len);

    if (ctx->command_end > ctx->command_start) {
        uint32_t len = (uint32_t)(ctx->command_end - ctx->command_start);
        if (len > WARMOR_CMDLINE_BYTES) {
            len = WARMOR_CMDLINE_BYTES; // truncated; userspace still gets a prefix
        }
        memcpy_s(rec->cmd, sizeof(rec->cmd), ctx->command_start, len);
        rec->cmd_len = (uint16_t)len;
    }

    if (rec->image_hash != 0) {
        rule = bpf_map_lookup_elem(&proc_deny, &rec->image_hash);
        if (rule != NULL && rule->action == WARMOR_ACTION_DENY) {
            if (rule->audit) {
                rec->hdr.verdict = WARMOR_VERDICT_AUDIT;
            } else {
                rec->hdr.verdict = WARMOR_VERDICT_BLOCKED;
                status = WARMOR_STATUS_ACCESS_DENIED;
            }
        }
    }

    bpf_ringbuf_output(&proc_events, rec, sizeof(*rec), 0);
    return status;
}
