# Building warmor

How to build warmor from source. For running it, see
[GETTING_STARTED.md](GETTING_STARTED.md) and [docs/operations.md](docs/operations.md).

## Prerequisites

**All platforms:** Go 1.26+ (see `go.mod`), Rust 1.70+ with the
`wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
for compiling YAML policies to WASM.

**Linux** additionally needs clang/LLVM and libbpf headers, but only when you
change `bpf/*.c` (see below):

```bash
# Ubuntu/Debian
sudo apt-get install -y libbpf-dev linux-headers-$(uname -r) clang llvm make gcc
# Fedora/RHEL
sudo dnf install -y libbpf-devel kernel-devel clang llvm make gcc
# Arch
sudo pacman -S libbpf linux-headers clang llvm make gcc
```

Kernel requirements for *running* are in
[docs/BPF_COMPATIBILITY.md](docs/BPF_COMPATIBILITY.md); building needs no
special kernel.

**Windows:** the Go toolchain; Visual Studio Build Tools only if you need
CGO. **macOS:** Xcode Command Line Tools, plus `CGO_ENABLED=1` to build the
ESF platform path (see [docs/PLATFORM_MACOS.md](docs/PLATFORM_MACOS.md)).

## Quick build

```bash
git clone https://github.com/yasindce1998/warmor.git && cd warmor
go build -o bin/ ./cmd/...     # every tool; no clang needed (see below)
```

The compiled BPF objects (`internal/ebpf/*_bpfel.o`, `*_bpfeb.o`) and their
generated Go bindings (`*_bpfel.go`, `*_bpfeb.go`) are **committed**, so a
plain `go build` works without clang. Regenerate them only when you change
`bpf/*.c`.

`make all` = `build-bpf` + `generate` + `build-policy` + `build-daemon`; it
needs clang and the Rust toolchain. `make tools` builds every `cmd/*` binary
into `./bin`.

## Rebuilding the eBPF objects and bindings

There are 11 BPF programs: 3 tracepoint monitors (`execve/openat/connect_monitor.bpf.c`),
7 LSM hooks (`lsm_{exec,file,connect,bind,listen,ptrace,mount}.bpf.c`) and
`lsm_integrity.bpf.c` (IMA exec integrity). The build order matters because
the Go bindings are generated from the compiled objects:

```bash
make build-bpf       # 1. compile bpf/*.c (clang)
make generate        # 2. bpf2go: generate Go bindings for both endiannesses
go build ./...       # 3. build
```

`make generate` runs `go generate` in `internal/ebpf`, which uses
[bpf2go](https://github.com/cilium/ebpf/cmd/bpf2go) to produce, per program,
`<name>_bpfel.go` + `<name>_bpfel.o` (little-endian) and
`<name>_bpfeb.go` + `<name>_bpfeb.o` (big-endian). Commit the regenerated
files with your change.

**Troubleshooting:**
- `bpf/bpf_helpers.h: No such file` → install `libbpf-dev`
- `linux/types.h: No such file` → install `linux-headers-$(uname -r)`
- `bpf2go: command not found` → `go install github.com/cilium/ebpf/cmd/bpf2go@latest`
  and make sure `$GOPATH/bin` is in `$PATH`
- `undefined: <name>Objects` in Go → the bindings are stale; rerun
  `make build-bpf generate`

## Make targets

| Target | Does |
|--------|------|
| `make all` | BPF objects + bindings + example policy + daemon |
| `make build-bpf` / `make generate` | Compile `bpf/*.c` / regenerate Go bindings |
| `make build-policy` | Build `policies/example/policy.wasm` (Rust) |
| `make build-daemon` | Build the daemon |
| `make tools` | Build every `cmd/*` binary into `./bin` |
| `make build-tests` | Build `test-ebpf` and `test-wasm` |
| `make test` | Run Go tests |
| `make bench` / `make bench-kernel` | Run the benchmark harness (see [docs/PERFORMANCE.md](docs/PERFORMANCE.md)) |
| `make deps` / `make clean` | Install dependencies / clean artifacts |

The 15 binaries under `cmd/` are listed in the
[README](README.md#policy-toolchain). Two are development helpers:
`test-ebpf` (loads the monitors and prints events) and `test-wasm`
(evaluates sample events against a policy). Neither needs root to build.

## Cross-compilation

```bash
# ARM64 Linux
GOARCH=arm64 go build -o bin/ ./cmd/...

# Windows (ETW path; no CGO needed)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/ ./cmd/...

# macOS — CGO_ENABLED=1 builds the ESF path and needs the macOS SDK,
# so cross-compiling macOS from Linux does not include ESF
GOOS=darwin GOARCH=arm64 go build -o bin/ ./cmd/...
```

## Windows eBPF programs (optional)

The eBPF-for-Windows programs are built as native, signed `.sys` images; see
[bpf-windows/README.md](bpf-windows/README.md). They are optional — the
daemon falls back to ETW when they are absent.

## Troubleshooting

- **"Permission denied" when running** — eBPF requires root: `sudo ./bin/warmor-daemon`
- **"Failed to load eBPF objects"** — check kernel version and BTF
  ([docs/BPF_COMPATIBILITY.md](docs/BPF_COMPATIBILITY.md)); regenerate
  bindings with `make build-bpf generate`
- **"malloc function not found" in WASM** — rebuild the policy:
  `cd policies/example && make clean && make`
- **First Rust build is slow** — normal; dependencies compile once
- **"can't find crate for `std`"** — `rustup target add wasm32-unknown-unknown`

## Platform guides

- **[Linux](docs/PLATFORM_LINUX.md)** — production (eBPF + LSM-BPF)
- **[Windows](docs/PLATFORM_WINDOWS.md)** — experimental (ETW + eBPF-for-Windows)
- **[macOS](docs/PLATFORM_MACOS.md)** — experimental, detection only (ESF)
