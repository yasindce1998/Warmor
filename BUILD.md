# Building warmor

This guide provides detailed instructions for building warmor from source.

## Prerequisites

### Platform-Specific Requirements

#### Linux (Production) ✅

**Required Tools:**

1. **Go 1.26.2+**
   ```bash
   go version
   # Should output: go version go1.26.2 or higher
   ```

2. **Rust 1.70+ with WASI target**
   ```bash
   rustc --version
   cargo --version
   
   # Add WASI target
   rustup target add wasm32-unknown-unknown
   ```

3. **Clang/LLVM** (for eBPF compilation)
   ```bash
   clang --version
   # Should output: clang version 10.0.0 or higher
   ```

4. **Linux Headers and BPF Development Files**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install -y \
       libbpf-dev \
       linux-headers-$(uname -r) \
       clang \
       llvm \
       make \
       gcc

   # Fedora/RHEL
   sudo dnf install -y \
       libbpf-devel \
       kernel-devel \
       clang \
       llvm \
       make \
       gcc

   # Arch Linux
   sudo pacman -S \
       libbpf \
       linux-headers \
       clang \
       llvm \
       make \
       gcc
   ```

**System Requirements:**
- **OS:** Linux with kernel 5.10+ (for eBPF support)
- **Architecture:** x86_64 or ARM64
- **Privileges:** Root access required for running (eBPF requirement)

#### Windows (Beta/Experimental) 🚧

**Required Tools:**

1. **Go 1.26.2+**
   ```powershell
   go version
   # Should output: go version go1.26.2 or higher
   ```

2. **Rust 1.70+ with WASI target**
   ```powershell
   rustc --version
   cargo --version
   
   # Add WASI target
   rustup target add wasm32-unknown-unknown
   ```

3. **Visual Studio Build Tools** (optional, for CGO)
   ```powershell
   winget install Microsoft.VisualStudio.2022.BuildTools
   ```

**System Requirements:**
- **OS:** Windows 10 version 1809+ or Windows 11
- **Architecture:** x64 only (ARM64 planned)
- **Privileges:** Administrator access required (for ETW)

**⚠️ Important:** Windows support is EXPERIMENTAL/BETA. ETW provides monitoring with post-facto enforcement (process termination via Win32 API) and sandbox primitives (Job Objects + Integrity Levels).

#### macOS (Beta/Experimental) 🚧

**Required Tools:**

1. **Go 1.26.2+**
   ```bash
   go version
   ```

2. **Rust 1.70+ with WASI target**
   ```bash
   rustc --version
   cargo --version
   
   # Add WASI target
   rustup target add wasm32-unknown-unknown
   ```

3. **Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

**System Requirements:**
- **OS:** macOS 10.15+ (Catalina or later)
- **Architecture:** x86_64 or ARM64 (Apple Silicon)
- **Privileges:** Root access required (for ESF)
- **Permissions:** System Extension approval + Full Disk Access

**⚠️ Important:** macOS support is EXPERIMENTAL/BETA. ESF provides monitoring and enforcement (AUTH events).

## Quick Build

### Linux

```bash
# Clone repository
git clone https://github.com/yasindce1998/warmor.git
cd warmor

# Install dependencies
make deps

# Build everything
make all
```

This will:
1. Compile the eBPF program
2. Generate Go bindings
3. Build the WASM policy
4. Build the warmor daemon (`./warmor-daemon`)
5. Build every CLI tool under `cmd/` into `./bin` (also `make tools` on its own)

### Windows (Beta)

```powershell
# Clone repository
git clone https://github.com/yasindce1998/warmor.git
cd warmor

# Build WASM policy
cd policies\example
cargo build --release --target wasm32-unknown-unknown
copy target\wasm32-unknown-unknown\release\warmor_policy_example.wasm policy.wasm
cd ..\..

# Build warmor daemon
$env:GOOS="windows"
$env:GOARCH="amd64"
$env:CGO_ENABLED="0"
go build -o warmor.exe cmd\warmor-daemon\main.go

# Verify
.\warmor.exe --version
```

**Note:** Windows build supports both ETW and eBPF-for-Windows modes.

#### Build eBPF Programs for Windows (Optional)

With eBPF-for-Windows installed, network (and, with ntosebpfext, process)
events are blocked in the kernel. The programs are built as native, signed
`.sys` images:

```powershell
cd bpf-windows
.\build.ps1 -EbpfIncludeDir <eBPF SDK include dir> `
            -NtosIncludeDir <ntosebpfext include dir> `
            -ConvertScript  <path to Convert-BpfToNative.ps1>
```

Copy `out\warmor_net.sys` and `out\warmor_proc.sys` into a `bpf\` directory
next to `warmor-daemon.exe`. See [bpf-windows/README.md](bpf-windows/README.md)
for signing requirements.

**Note:** eBPF programs are optional. warmor will automatically fall back to ETW if eBPF-for-Windows is not available.

### macOS (Beta/Experimental)

```bash
# Clone repository
git clone https://github.com/yasindce1998/warmor.git
cd warmor

# Install Xcode Command Line Tools (if not already installed)
xcode-select --install

# Build WASM policy
cd policies/example
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/warmor_policy_example.wasm policy.wasm
cd ../..

# Build warmor daemon with ESF support
export GOOS=darwin
export GOARCH=amd64  # or arm64 for Apple Silicon
export CGO_ENABLED=1

go build -o warmor-daemon cmd/warmor-daemon/main.go

# Verify
./warmor-daemon --version
```

**Note:** macOS build uses Endpoint Security Framework (ESF) for monitoring and enforcement.

#### Code Signing (Required for Distribution)

```bash
# Sign the binary
codesign --sign "Developer ID Application: Your Name" \
         --entitlements macos/SystemExtension/warmor.entitlements \
         --options runtime \
         warmor-daemon

# Verify signature
codesign -dv --verbose=4 warmor-daemon
```

#### Create System Extension Bundle

```bash
# Create bundle structure
mkdir -p warmor.app/Contents/MacOS
mkdir -p warmor.app/Contents/Resources

# Copy binary
cp warmor-daemon warmor.app/Contents/MacOS/

# Copy Info.plist
cp macos/SystemExtension/Info.plist warmor.app/Contents/

# Sign the bundle
codesign --sign "Developer ID Application: Your Name" \
         --entitlements macos/SystemExtension/warmor.entitlements \
         --options runtime \
         warmor.app
```

#### Running on macOS

```bash
# Run as root (REQUIRED for ESF)
sudo ./warmor-daemon

# Run with custom policy
sudo ./warmor-daemon -policy policies/example/policy.wasm
```

**First Run Setup:**
1. Grant Full Disk Access: System Preferences → Security & Privacy → Privacy → Full Disk Access
2. Approve System Extension when prompted
3. Verify: run `sudo ./warmor-daemon` — it logs a warning if Full Disk Access or System Extension approval is missing

**Note:** See [macOS Platform Guide](docs/PLATFORM_MACOS.md) for detailed setup instructions.

## Step-by-Step Build

### Step 1: Install Go Dependencies

```bash
go mod download
```

### Step 2: Build eBPF Program

```bash
cd bpf
make
cd ..
```

This compiles `execve_monitor.bpf.c` to `execve_monitor.bpf.o`.

**Troubleshooting:**
- If you get "bpf/bpf_helpers.h: No such file", install `libbpf-dev`
- If you get "linux/types.h: No such file", install `linux-headers-$(uname -r)`

### Step 3: Generate eBPF Go Bindings

```bash
go generate ./internal/ebpf
```

This creates:
- `internal/ebpf/execve_monitor_bpfeb.go` (big-endian)
- `internal/ebpf/execve_monitor_bpfel.go` (little-endian)
- `internal/ebpf/execve_monitor_bpfeb.o`
- `internal/ebpf/execve_monitor_bpfel.o`

**Troubleshooting:**
- If you get "bpf2go: command not found", run: `go install github.com/cilium/ebpf/cmd/bpf2go@latest`
- Make sure `$GOPATH/bin` is in your `$PATH`

### Step 4: Build WASM Policy

```bash
cd policies/example
make
cd ../..
```

This compiles the Rust policy to `policies/example/policy.wasm`.

**Troubleshooting:**
- If you get "error: can't find crate for `std`", add the WASM target: `rustup target add wasm32-unknown-unknown`
- If build is slow, it's normal for the first build (Rust compiles dependencies)

### Step 5: Build warmor Daemon

```bash
go build -o warmor-daemon ./cmd/warmor-daemon
```

**Troubleshooting:**
- If you get import errors, run `go mod tidy`
- If you get eBPF-related errors, make sure Step 3 completed successfully

### Step 6: Build warmor-compile CLI

```bash
go build -o warmor-compile ./cmd/warmor-compile
```

This builds the YAML-to-WASM policy compiler. Requires Rust + wasm32-unknown-unknown target for actual compilation, but validation (`--validate`) works without Rust.

### Step 7: Build Test Tools (Optional)

```bash
go build -o test-ebpf ./cmd/test-ebpf
go build -o test-wasm ./cmd/test-wasm
```

## Build Targets

### All Targets

```bash
make all          # Build everything
make build-bpf    # Build eBPF program only
make generate     # Generate eBPF Go bindings only
make build-policy # Build WASM policy only
make build-daemon # Build warmor daemon only
make tools        # Build every cmd/* binary into ./bin
make build-tests  # Build test tools only
make test         # Run Go tests
make clean        # Clean all build artifacts
make deps         # Install dependencies
```

### Building warmor-compile

```bash
# Build the compiler CLI
go build -o warmor-compile ./cmd/warmor-compile

# Compile a YAML policy
./warmor-compile my-policy.yaml -o my-policy.wasm

# Emit Rust source only (no cargo needed)
./warmor-compile --rust-only my-policy.yaml > policy.rs

# Validate without compiling
./warmor-compile --validate my-policy.yaml
```

### Building the Helm Chart

```bash
# Lint the chart
helm lint deploy/helm/warmor/

# Template (verify rendered manifests)
helm template warmor deploy/helm/warmor/

# Package for distribution
helm package deploy/helm/warmor/
```

## Verification

### Verify eBPF Build

```bash
ls -lh bpf/execve_monitor.bpf.o
# Should show a file around 5-10KB
```

### Verify Go Bindings

```bash
ls -lh internal/ebpf/execve_monitor_bpf*.go
# Should show 2 .go files and 2 .o files
```

### Verify WASM Policy

```bash
ls -lh policies/example/policy.wasm
# Should show a file around 100-500KB
```

### Verify Daemon Binary

```bash
ls -lh warmor-daemon
# Should show an executable file around 10-20MB

./warmor-daemon -h
# Should show help message
```

## Running Tests

### Linux Tests

#### Test eBPF Event Capture

```bash
sudo ./test-ebpf
```

Expected output:
```
warmor eBPF Test Tool
Testing eBPF event capture...
✓ eBPF program loaded and attached successfully
Monitoring execve syscalls... Press Ctrl+C to stop

[1] PID=1234 UID=1000 GID=1000 COMM=bash FILENAME=/usr/bin/ls TIME=14:30:00.123
[2] PID=1235 UID=1000 GID=1000 COMM=bash FILENAME=/usr/bin/cat TIME=14:30:01.456
```

### Test WASM Policy Evaluation

```bash
./test-wasm
```

Expected output:
```
warmor WASM Test Tool
Testing WASM policy evaluation...
✓ WASM runtime created
✓ Policy loaded
✓ Policy instance created

Testing policy evaluation with sample events:

[1] ✗ [DENY] PID=1234 UID=0 COMM=bash FILE=/bin/bash (eval_time=45µs)
[2] 📝 [LOG] PID=1235 UID=1000 COMM=python3 FILE=/usr/bin/python3 (eval_time=52µs)
[3] ✓ [ALLOW] PID=1236 UID=1000 COMM=ls FILE=/usr/bin/ls (eval_time=48µs)

=== Test Summary ===
Total Events: 5
Successful Evaluations: 5
Failed Evaluations: 0
Average Evaluation Time: 49µs
====================

✓ All tests passed!
```

#### Run Full Enforcer (Linux)

```bash
sudo ./warmor-daemon
```

Expected output:
```
╦ ╦╔═╗╦═╗╔╦╗╔═╗╦═╗
║║║╠═╣╠╦╝║║║║ ║╠╦╝
╚╩╝╩ ╩╩╚═╩ ╩╚═╝╩╚═
WASM-Powered Security Enforcer
Version: 1.1.0-beta

Policy: policies/example/policy.wasm
Platform: linux (eBPF)
Stats Interval: 30s
Log Level: info

Initializing warmor enforcer...
Loading eBPF program...
✓ eBPF program loaded
Creating WASM runtime...
✓ WASM runtime created
Loading policy from: policies/example/policy.wasm
✓ Policy loaded
Creating policy instance...
✓ Policy instance created

✓ warmor enforcer initialized successfully

Enforcer started, processing events...
🚀 warmor is running. Press Ctrl+C to stop.

[DENY] PID=1234 UID=0 COMM=sudo FILE=/bin/bash (eval_time=45µs)
[LOG] PID=1235 UID=1000 COMM=bash FILE=/usr/bin/python3 (eval_time=52µs)
```

### Windows Tests (Beta)

#### Run warmor on Windows

```powershell
# Run as Administrator (REQUIRED)
.\warmor.exe

# Or with custom policy
.\warmor.exe --policy policies\cross-platform\target\wasm32-unknown-unknown\release\cross_platform_policy.wasm

# With debug logging
.\warmor.exe --log-level debug
```

Expected output:
```
╦ ╦╔═╗╦═╗╔╦╗╔═╗╦═╗
║║║╠═╣╠╦╝║║║║ ║╠╦╝
╚╩╝╩ ╩╩╚═╩ ╩╚═╝╩╚═
WASM-Powered Security Enforcer
Version: 1.1.0-beta (EXPERIMENTAL)

Policy: policies\cross-platform\target\wasm32-unknown-unknown\release\cross_platform_policy.wasm
Platform: windows (ETW - Beta)
Stats Interval: 30s
Log Level: info

⚠️  WARNING: Windows support is EXPERIMENTAL/BETA
⚠️  Enforcement: post-facto (process termination after detection)

Initializing warmor enforcer...
Windows platform: Initializing ETW consumer
Note: Windows support is EXPERIMENTAL/BETA
Enabling process monitoring...
Enabling file monitoring...
Enabling network monitoring...
Windows platform started successfully
Creating WASM runtime...
✓ WASM runtime created
Loading policy from: policies\cross-platform\target\wasm32-unknown-unknown\release\cross_platform_policy.wasm
✓ Policy loaded

✓ warmor enforcer initialized successfully

Enforcer started, processing events...
🚀 warmor is running. Press Ctrl+C to stop.

[LOG] PID=1234 UID=1000 COMM=notepad.exe FILE=C:\Windows\System32\notepad.exe
[LOG] PID=1235 UID=1000 COMM=powershell.exe FILE=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Troubleshooting Windows:**
- **"Access Denied"** - Run PowerShell as Administrator
- **"ETW session already exists"** - Stop existing session: `logman stop "WarmorETWSession" -ets`
- **No events appearing** - Check Event Viewer for ETW errors

### macOS Tests (Beta)

```bash
# Run as root (REQUIRED for ESF)
sudo ./warmor-daemon
```

Expected output:
```
╦ ╦╔═╗╦═╗╔╦╗╔═╗╦═╗
║║║╠═╣╠╦╝║║║║ ║╠╦╝
╚╩╝╩ ╩╩╚═╩ ╩╚═╝╩╚═
WASM-Powered Security Enforcer
Version: 1.1.0-beta

macOS platform: Initializing Endpoint Security Framework
Note: macOS support is EXPERIMENTAL/BETA
Note: Requires Full Disk Access and System Extension approval
✓ macOS platform loaded (ESF mode)
Subscribing to process events...
Subscribing to file events...
Subscribing to network events...
✓ macOS platform started successfully
⚠️  Make sure to grant Full Disk Access in System Preferences
```

## Build Options

### Debug Build

```bash
go build -gcflags="all=-N -l" -o warmor-daemon ./cmd/warmor-daemon
```

### Optimized Build

```bash
go build -ldflags="-s -w" -o warmor-daemon ./cmd/warmor-daemon
```

### Static Binary

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o warmor-daemon ./cmd/warmor-daemon
```

Note: Static builds may not work with eBPF due to CGO requirements in cilium/ebpf.

## Cross-Compilation

### Linux Cross-Compilation

For different architectures:

```bash
# ARM64
GOARCH=arm64 go build -o warmor-daemon-arm64 ./cmd/warmor-daemon

# x86_64
GOARCH=amd64 go build -o warmor-daemon-amd64 ./cmd/warmor-daemon
```

### Windows Cross-Compilation (from Linux)

```bash
# Build for Windows from Linux
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o warmor.exe cmd/warmor-daemon/main.go
```

### macOS Cross-Compilation (from Linux)

```bash
# Build for macOS from Linux
GOOS=darwin GOARCH=amd64 go build -o warmor-darwin cmd/warmor-daemon/main.go

# For Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o warmor-darwin-arm64 cmd/warmor-daemon/main.go
```

## Troubleshooting

### "Permission denied" when running

eBPF requires root privileges:
```bash
sudo ./warmor-daemon
```

### "Failed to load eBPF objects"

1. Check kernel version: `uname -r` (need 5.10+)
2. Check if eBPF is enabled: `zgrep CONFIG_BPF /proc/config.gz`
3. Regenerate bindings: `go generate ./internal/ebpf`

### "malloc function not found" in WASM

Rebuild the policy:
```bash
cd policies/example
make clean
make
cd ../..
```

### Build is very slow

First Rust build compiles all dependencies. Subsequent builds are much faster.

### "undefined reference" errors

Make sure all dependencies are installed:
```bash
make deps
go mod tidy
```

## Clean Build

To start fresh:

```bash
make clean
rm -rf internal/ebpf/execve_monitor_bpf*.go
rm -rf internal/ebpf/execve_monitor_bpf*.o
make all
```

## Next Steps

After successful build:

1. **Test the components** - Run test-ebpf and test-wasm
2. **Run the enforcer** - `sudo ./warmor-daemon`
3. **Customize the policy** - Edit `policies/example/src/lib.rs`
4. **Read the docs** - See [GETTING_STARTED.md](GETTING_STARTED.md)

## Getting Help

- **Build Issues:** Check [GitHub Issues](https://github.com/yasindce1998/warmor/issues)
- **Documentation:** See [docs/](docs/) directory
- **Architecture:** [docs/architecture.md](docs/architecture.md)

---

## Platform-Specific Documentation

For detailed platform-specific information:

- **[Linux Platform Guide](docs/PLATFORM_LINUX.md)** - Production (eBPF)
- **[Windows Platform Guide](docs/PLATFORM_WINDOWS.md)** - Beta/Experimental (ETW + eBPF-for-Windows)
- **[macOS Platform Guide](docs/PLATFORM_MACOS.md)** - Beta/Experimental (ESF)

---

**Last Updated:** 2026-06-10  
**Version:** 1.1.0-beta (Phase 5 Complete)