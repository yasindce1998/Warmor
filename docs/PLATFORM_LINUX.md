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
│  - execve_monitor.bpf.c             │
│  - openat_monitor.bpf.c             │
│  - connect_monitor.bpf.c            │
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
- **Minimum:** Linux 5.8+ (for CO-RE support)
- **Recommended:** Linux 5.15+ (LTS)
- **Optimal:** Linux 6.0+ (latest features)

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

This creates:
- `internal/ebpf/execve_bpfel.go` - eBPF program bindings
- `internal/ebpf/execve_bpfel.o` - Embedded eBPF bytecode

### 3. Build warmor
```bash
GOOS=linux GOARCH=amd64 go build -o warmor cmd/warmor/main.go
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

### Systemd Service
Create `/etc/systemd/system/warmor.service`:
```ini
[Unit]
Description=Warmor Security Enforcer
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/warmor --policy /etc/warmor/policy.wasm
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
- Arguments (up to 5)
- Parent PID

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
    ProcessMonitoring: true,  // ✅ Full support
    FileMonitoring:    true,  // ✅ Full support
    NetworkMonitoring: true,  // ✅ Full support
    Enforcement:       true,  // ✅ Can block syscalls
}
```

## Performance

### Overhead
- **Per-event latency:** <10μs
- **CPU overhead:** <1% on typical workloads
- **Memory overhead:** ~10MB for eBPF maps

### Optimization Tips
1. **Use BPF maps for caching** - Reduce userspace roundtrips
2. **Filter events in kernel** - Only send relevant events
3. **Batch event processing** - Process multiple events together
4. **Use CO-RE** - Avoid BTF generation overhead

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
sudo aa-complain /usr/local/bin/warmor
```

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