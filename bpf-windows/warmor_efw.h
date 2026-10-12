// SPDX-License-Identifier: MIT
// Copyright (c) 2026 warmor
//
// Shared definitions for Warmor's eBPF-for-Windows programs.
//
// Record and key layouts are mirrored in internal/platform/efw/records.go and
// must stay byte-for-byte identical; the Go side has tests pinning every
// offset. All multi-byte integers are little-endian except ports and
// addresses, which stay in network byte order as the hooks report them.

#ifndef WARMOR_EFW_H
#define WARMOR_EFW_H

#include "bpf_helpers.h"

// ── Record kinds (warmor_rec_hdr.kind) ─────────────────────────────────────
#define WARMOR_REC_PROCESS_CREATE 1
#define WARMOR_REC_PROCESS_EXIT   2
#define WARMOR_REC_NETWORK        3

// ── Verdicts (warmor_rec_hdr.verdict) ──────────────────────────────────────
#define WARMOR_VERDICT_ALLOWED 0 // no kernel rule matched
#define WARMOR_VERDICT_BLOCKED 1 // a deny rule matched and the kernel blocked
#define WARMOR_VERDICT_AUDIT   2 // an audit deny rule matched; allowed

// ── Policy actions (warmor_policy_value.action) ────────────────────────────
#define WARMOR_ACTION_ALLOW 0
#define WARMOR_ACTION_DENY  1

// ── Network directions ─────────────────────────────────────────────────────
#define WARMOR_DIR_CONNECT 0 // connect4/6: TCP connect or first UDP send to a tuple
#define WARMOR_DIR_ACCEPT  1 // recv_accept4/6: TCP accept or first UDP receive

// Windows address families.
#define WARMOR_AF_INET  2
#define WARMOR_AF_INET6 23

// Image path buffer, in UTF-16 code units (winutil.ImagePathMaxChars).
#define WARMOR_IMAGE_PATH_CHARS 512
// Command line bytes copied into process records.
#define WARMOR_CMDLINE_BYTES 2048

// NTSTATUS returned by the process hook to deny a creation.
#define WARMOR_STATUS_ACCESS_DENIED ((int)0xC0000022)

// ── Records sent to userspace over the ring buffers ────────────────────────

// 16 bytes.
struct warmor_rec_hdr
{
    uint32_t kind;
    uint32_t verdict;
    uint64_t pid;
};

// 3120 bytes. Too large for the 512-byte BPF stack; built in a per-CPU
// scratch map.
struct warmor_proc_rec
{
    struct warmor_rec_hdr hdr;                      // 0
    uint64_t ppid;                                  // 16
    uint64_t creation_time;                         // 24 FILETIME
    uint64_t image_hash;                            // 32 0 = not matchable
    uint32_t exit_code;                             // 40
    uint16_t image_len;                             // 44 bytes, excluding NUL
    uint16_t cmd_len;                               // 46 bytes
    uint8_t image[WARMOR_IMAGE_PATH_CHARS * 2];     // 48 UTF-16LE NT path
    uint8_t cmd[WARMOR_CMDLINE_BYTES];              // 1072 UTF-16LE
};

// 24 bytes.
struct warmor_proc_exit_rec
{
    struct warmor_rec_hdr hdr; // 0
    uint32_t exit_code;        // 16
    uint32_t pad;              // 20
};

// 64 bytes.
struct warmor_net_rec
{
    struct warmor_rec_hdr hdr; // 0
    uint64_t image_hash;       // 16 0 = process not tracked yet
    uint8_t family;            // 24
    uint8_t direction;         // 25
    uint8_t protocol;          // 26 IPPROTO_*
    uint8_t pad;               // 27
    uint16_t remote_port;      // 28 network order
    uint16_t local_port;       // 30 network order
    uint8_t remote_addr[16];   // 32 IPv4 uses the first 4 bytes
    uint8_t local_addr[16];    // 48
};

// ── Map keys and values ────────────────────────────────────────────────────

// proc_deny key: image hash. Value: warmor_policy_value.
// net_policy key, 32 bytes. Value: warmor_policy_value.
struct warmor_net_key
{
    uint64_t image_hash;  // 0
    uint8_t family;       // 8
    uint8_t direction;    // 9
    uint8_t protocol;     // 10
    uint8_t pad;          // 11
    uint16_t port;        // 12 remote port, network order
    uint16_t pad2;        // 14
    uint8_t addr[16];     // 16 remote address
};

// 4 bytes.
struct warmor_policy_value
{
    uint8_t action;
    uint8_t audit;
    uint16_t pad;
};

// proc_info value, keyed by uint32_t PID. Written by userspace from process
// events so the network hooks can tell which image is connecting.
struct warmor_proc_info
{
    uint64_t image_hash;
};

// ── Image hashing ──────────────────────────────────────────────────────────

#define WARMOR_FNV64_OFFSET 14695981039346656037ULL
#define WARMOR_FNV64_PRIME  1099511628211ULL

// FNV-1a 64 over a NUL-terminated UTF-16LE path, ASCII-lowercased, low byte
// first. Returns 0 for empty paths and for paths that fill the buffer (they
// may be truncated). Must match winutil.ImageHash.
static __inline uint64_t
warmor_image_hash(const uint8_t* path, uint16_t* out_len)
{
    uint64_t h = WARMOR_FNV64_OFFSET;
    uint32_t i;

    for (i = 0; i < WARMOR_IMAGE_PATH_CHARS; i++) {
        uint16_t c = (uint16_t)path[2 * i] | ((uint16_t)path[2 * i + 1] << 8);
        if (c == 0) {
            break;
        }
        if (c >= 'A' && c <= 'Z') {
            c += 'a' - 'A';
        }
        h ^= (uint64_t)(c & 0xff);
        h *= WARMOR_FNV64_PRIME;
        h ^= (uint64_t)(c >> 8);
        h *= WARMOR_FNV64_PRIME;
    }

    *out_len = (uint16_t)(i * 2);
    if (i == 0 || i >= WARMOR_IMAGE_PATH_CHARS - 1) {
        return 0;
    }
    return h == 0 ? 1 : h;
}

#endif // WARMOR_EFW_H
