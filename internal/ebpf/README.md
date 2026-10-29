# eBPF Package

This package provides the eBPF loader for warmor.

## Build Order

**IMPORTANT:** This package has a specific build order due to code generation:

1. **First:** Compile the eBPF C program
   ```bash
   cd ../../bpf
   make
   ```

2. **Second:** Generate Go bindings
   ```bash
   cd ../internal/ebpf
   go generate
   ```
   
   This will create:
   - `execve_monitor_bpfeb.go` (big-endian)
   - `execve_monitor_bpfel.go` (little-endian)
   - `execve_monitor_bpfeb.o`
   - `execve_monitor_bpfel.o`

3. **Third:** Build Go code
   ```bash
   go build
   ```

## Generated Files

The `go generate` command uses `bpf2go` to generate Go bindings from the eBPF C code. The generated bindings and compiled objects **are** checked into git, so a plain `go build ./...` works without clang; regenerate them only when you change `bpf/*.c`.

### What Gets Generated

- **Type Definitions:** Go structs matching C structs (e.g., `execve_event`)
- **Object Loaders:** Functions to load eBPF programs (e.g., `loadExecve_monitorObjects`)
- **Map Accessors:** Access to eBPF maps (e.g., `Events` ring buffer)
- **Program References:** References to eBPF programs (e.g., `TracepointSyscallsSysEnterExecve`)

## Usage

```go
import "github.com/yasindce1998/warmor/internal/ebpf"

// Load eBPF program
loader, err := ebpf.Load()
if err != nil {
    log.Fatal(err)
}
defer loader.Close()

// Read process events (also: ReadFileEvent, ReadNetworkEvent)
for {
    event, err := loader.ReadProcessEvent()
    if err != nil {
        log.Printf("Error: %v", err)
        continue
    }
    
    log.Printf("PID=%d UID=%d COMM=%s FILE=%s",
        event.PID, event.UID, event.Comm, event.Filename)
}
```

## Troubleshooting

### "undefined: execve_monitorObjects"

This means the Go bindings haven't been generated yet. Run:
```bash
cd ../../bpf && make && cd ../internal/ebpf
go generate
```

### "bpf2go: command not found"

Install bpf2go:
```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

Make sure `$GOPATH/bin` is in your `$PATH`.

### "Failed to load eBPF objects"

1. Check kernel version: `uname -r` (need 5.7 minimum, 5.8+ recommended — see `docs/BPF_COMPATIBILITY.md`)
2. Check if eBPF is enabled: `zgrep CONFIG_BPF /proc/config.gz`
3. Run with root: `sudo ./your-program`

## Files

- `loader.go` - Main eBPF loader implementation
- `events.go` - Event structures and conversion
- `README.md` - This file
- `*_bpfeb.go` / `*_bpfel.go` - Generated Go bindings (committed)
- `*_bpfeb.o` / `*_bpfel.o` - Generated eBPF objects (committed)

## Dependencies

- `github.com/cilium/ebpf` - eBPF library for Go
- `github.com/cilium/ebpf/cmd/bpf2go` - Code generator
- Linux kernel 5.7+ (5.8+ recommended) with eBPF support — see `docs/BPF_COMPATIBILITY.md`
- `libbpf-dev` and `linux-headers` packages

---

**Note:** Always use `make all` from the project root to ensure correct build order.