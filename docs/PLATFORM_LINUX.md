# Linux Platform Guide

This guide covers warmor's Linux implementation using eBPF (Extended Berkeley Packet Filter).

## Architecture

```
┌─────────────────────────────────────┐
│         WASM Policy Engine          │
│    (Portable, Platform-Agnostic)    │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│    Platform Abstraction Layer       │
│         (interface.go)              │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│      Linux Platform (linux.go)      │
│    - eBPF program management        │
│    - Event collection               │
│    - Enforcement hooks              │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│         eBPF Programs (BPF)         │
│  Tracepoints (observe):             │
│  - execve_monitor.bpf.c             │
│  - openat_monitor.bpf.c             │
│  - connect_monitor.bpf.c            │
│  LSM hooks (can block):             │
│  - lsm_exec / lsm_file / lsm_connect│
│  - lsm_bind / lsm_listen            │
│  - lsm_ptrace / lsm_mount           │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│         Linux Kernel                │
│    - Syscall interception           │
│    - Event generation               │
└─────────────────────────────────────┘
```

## Requirements

### Kernel Version

The canonical kernel requirements and the tested-kernel matrix live in
[BPF_COMPATIBILITY.md](BPF_COMPATIBILITY.md). In short: 5.7 minimum (the
`lsm/*` attach type), 5.8+ recommended (ring buffer maps), `CONFIG_BPF_LSM=y`
and `bpf` in the active LSM list for kernel blocking, and BTF for CO-RE.
CI currently exercises the LSM programs on 6.1, 6.18 and the stable/mainline
ci-kernels channels.

### Kernel Configuration
Required kernel options:
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_BPF_LSM=y
```

For LSM enforcement, `bpf` must also appear in the active LSM list at boot:
```
# /proc/cmdline or GRUB: lsm=lockdown,capability,...,bpf
```

Check your kernel:
```bash
# Check kernel version
uname -r

# Check BPF support
zgrep CONFIG_BPF /proc/config.gz

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Check BPF LSM is active
cat /sys/kernel/security/lsm   # should contain "bpf"
```

#### WSL2 Note

On WSL2, securityfs may not be auto-mounted. If `/sys/kernel/security/lsm` is
missing, mount it manually:
```bash
sudo mount -t securityfs none /sys/kernel/security
```
Warmor's `IsLSMSupported()` also falls back to parsing `/proc/cmdline`, so the
agent starts correctly either way.

### Build Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential

# Fedora/RHEL
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    make

# Arch Linux
sudo pacman -S clang llvm libbpf linux-headers
```

## Building

### 1. Build eBPF Programs
```bash
cd bpf
make
```

This generates:
- `execve_monitor.bpf.o` - Process execution monitoring
- `openat_monitor.bpf.o` - File operation monitoring
- `connect_monitor.bpf.o` - Network connection monitoring

### 2. Generate Go Bindings
```bash
go generate ./internal/ebpf/...
```

This creates (for each program, both endiannesses):
- `internal/ebpf/execve_monitor_bpfel.go` - eBPF program bindings
- `internal/ebpf/execve_monitor_bpfel.o` - Embedded eBPF bytecode

The generated bindings and objects are committed, so steps 1-2 are only needed
after changing `bpf/*.c`.

### 3. Build warmor
```bash
go build -o bin/ ./cmd/...
```

## Running

### Basic Usage
```bash
# Audit first (deny decisions logged, nothing killed)
sudo ./warmor-daemon --policy /path/to/policy.wasm --audit

# Enforce (SIGKILL on deny; cached exec/connect denies blocked in-kernel)
sudo ./warmor-daemon --policy /path/to/policy.wasm --lsm-enforce

# The BPF programs are embedded in the binary; there is no --ebpf-dir flag.
# The default --policy (policies/example/policy.wasm) is a starter example;
# pass your own policy and start with --audit. See docs/STATUS.md.
```

### Event delivery under load

The kernel hooks queue events in a ring buffer (4 MiB by default) for the
daemon to evaluate. If the ring is full, an event is **dropped**: the hook has
already allowed the operation, so it is never evaluated. Every drop is counted
per hook in `warmor_lsm_events_dropped_total`, logged every 5 s, and the
shipped alert rules fire on any drop.

```bash
# Bigger ring for bursty hosts (power of two)
sudo ./warmor-daemon --policy policy.wasm --lsm-enforce --lsm-ringbuf-size 16MiB

# Fail closed: refuse unknown execs and connects whose event can't be queued
sudo ./warmor-daemon --policy policy.wasm --lsm-enforce --on-event-loss deny
```

`--on-event-loss=deny` only applies in enforce mode and only to exec and
connect, and it can refuse legitimate operations during a flood. The default
(`log`) keeps them allowed and counted. Scoping the daemon to pod cgroups
(`--cgroup-filter auto`) is the most effective way to reduce volume, because
`file_open` sends an event for every open in scope.

### Systemd Service
Create `/etc/systemd/system/warmor.service`:
```ini
[Unit]
Description=Warmor Security Enforcer
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/warmor-daemon --policy /etc/warmor/policy.wasm --lsm-enforce
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable warmor
sudo systemctl start warmor
```

## eBPF Programs

### execve_monitor.bpf.c
Monitors process execution via `execve()` syscall.

**Captured Data:**
- PID, UID, GID
- Command name
- Executable path
- Cgroup ID

(Exec arguments and the parent PID are not captured; the WASM policy never
sees them.)

**Hook Point:** `tracepoint/syscalls/sys_enter_execve`

### openat_monitor.bpf.c
Monitors file operations via `openat()` syscall.

**Captured Data:**
- PID, UID, GID
- File path
- Open flags (O_RDONLY, O_WRONLY, etc.)
- File mode

**Hook Point:** `tracepoint/syscalls/sys_enter_openat`

### connect_monitor.bpf.c
Monitors network connections via `connect()` syscall.

**Captured Data:**
- PID, UID, GID
- Destination IP address
- Destination port
- Protocol (TCP/UDP)

**Hook Point:** `tracepoint/syscalls/sys_enter_connect`

## Capabilities

The Linux platform provides full monitoring and enforcement:

```go
Capabilities{
    ProcessMonitoring: true,   // ✅ Full support
    FileMonitoring:    true,   // ✅ Full support
    NetworkMonitoring: true,   // ✅ Full support
    Enforcement:       true,   // ✅ SIGKILL on userspace deny
    LSMEnforcement:    true,   // ✅ In-kernel -EPERM for cached exec/connect denies (--lsm-enforce)
}
```

## Performance

Measured numbers (with methodology and caveats) are in
[PERFORMANCE.md](PERFORMANCE.md). Highlights on the benchmark hardware:
P95 cache hit 1.2–1.3 µs; P95 cache miss 32 µs (YAML policy); kernel fast
path 0.11 µs (connect) / 0.34 µs (exec); 175k events/s declared throughput;
11% of one core at 10k events/s.

### Optimization Tips
1. **Scope with `--cgroup-filter`** - the biggest lever; `file_open` emits an event for every open in scope
2. **Use declared policies** - compiled YAML policies export their fields-read, enabling decision-cache hits
3. **Size the ring buffer** - `--lsm-ringbuf-size` for bursty hosts (drops are counted in `warmor_lsm_events_dropped_total`)

## Debugging

### Check eBPF Programs
```bash
# List loaded programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id <ID>

# Dump program instructions
sudo bpftool prog dump xlated id <ID>
```

### Check eBPF Maps
```bash
# List maps
sudo bpftool map list

# Show map contents
sudo bpftool map dump id <ID>
```

### Trace Events
```bash
# Enable tracing
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Filter by program
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep warmor
```

### Common Issues

**Issue:** `failed to load eBPF program: permission denied`
**Solution:** Run with `sudo` or add `CAP_BPF` capability

**Issue:** `BTF not found`
**Solution:** Install kernel headers or enable `CONFIG_DEBUG_INFO_BTF`

**Issue:** `program too large`
**Solution:** Reduce program complexity or increase verifier limits

## Security Considerations

### Privileges Required
- **CAP_BPF** - Load eBPF programs
- **CAP_PERFMON** - Attach to tracepoints
- **CAP_NET_ADMIN** - Network monitoring

### Kernel Lockdown
If kernel lockdown is enabled:
```bash
# Check lockdown status
cat /sys/kernel/security/lockdown

# Disable for development (not recommended for production)
sudo sysctl kernel.lockdown=0
```

### SELinux/AppArmor
Create appropriate policies to allow eBPF operations:

**SELinux:**
```bash
sudo semanage permissive -a warmor_t
```

**AppArmor:**
```bash
sudo aa-complain /usr/local/bin/warmor-daemon
```

## Enforcement-Related Flags

| Flag | Default | Effect |
|------|---------|--------|
| `--lsm-enforce` | `false` | Arm kernel blocking for exec/connect `DENY` rules already in the policy map. Without it the LSM programs run audit-only (denied processes are still `SIGKILL`ed from userspace). |
| `--require-lsm` | `false` | Refuse to start unless the LSM programs load and arm. Without it the daemon degrades to tracepoint-only observe mode with a warning. |
| `--no-lsm` | `false` | Skip LSM-BPF entirely (tracepoint-only). |
| `--audit` | `false` | Log would-be denials; kill and block nothing. The only true dry-run mode. |
| `--lsm-ringbuf-size` | `4 MiB` | Size of the LSM event ring buffer (power of two). Bigger rings absorb bursts. |
| `--on-event-loss` | `log` | What to do when the ring is full: `log` (default; dropped events are counted per hook) or `deny` (fail closed: refuse unknown execs/connects whose event could not be queued; enforce mode only). |
| `--cgroup-filter` | — | Restrict the LSM programs to the given cgroup paths, or `auto` for pod cgroups. |
| `--verify-key` | — | Ed25519 public key PEM; require a valid detached `<policy>.sig` at startup, on reload and on every policy-server download. Fails closed. See [policy-bundle.md](policy-bundle.md#detached-signatures-daemon-and-policy-server). |
| `--integrity-db` / `--integrity-mode` | — | Content-hash exec integrity: a sleepable LSM program hashes each exec with IMA and refuses (`enforce`) or reports (`audit`) binaries whose SHA-256 is not in the database. Requires `CONFIG_IMA` with SHA-256. See [supply-chain-integrity.md](supply-chain-integrity.md). |
| `--escape-detect` | — | `alert` or `deny`: match container-breakout patterns (mount sources, cross-cgroup ptrace, runtime socket connects) on container cgroups. `deny` also terminates the process. See [escape-detection.md](escape-detection.md). |
| `--eval-timeout` | `50ms` | Per-evaluation WASM deadline; a policy exceeding it fails closed (DENY). |

Posture guidance for combining these flags is in
[SECURITY_POSTURE.md](SECURITY_POSTURE.md).

## Limitations

1. **Kernel Version Dependency** - Requires modern kernel (5.8+)
2. **BTF Requirement** - Needs BTF information for CO-RE
3. **Verifier Limits** - Complex programs may hit verifier limits
4. **No Userspace Tracing** - Only kernel-level syscalls

## Future Enhancements

- [ ] Support for more syscalls (read, write, unlink, etc.)
- [ ] Performance counters and statistics
- [ ] Dynamic program loading/unloading

## References

- [eBPF Documentation](https://ebpf.io/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [BPF CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/)
- [Linux Tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)