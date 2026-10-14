# Rust WASM Policy Examples

> **Status on `main`: example crates have known ABI bugs (being fixed).** Use YAML policies compiled with `warmor-compile` for anything you plan to enforce.
> - `container-escape`, `crypto-mining`, `lateral-movement`, `multi` and `supply-chain` export a JSON `evaluate_event`. The host treats an export with that name as its binary ABI, so these crates **deny every event**.
> - `advanced`, `example` and `zero-trust-net` require a `filename` field that the host omits for file and network events, so they **deny every file and network event**.
> - `cross-platform` and `temporal-access` do not compile.
> - The `abi_version` export is never checked, and CI builds none of these crates.
>
> See [Feature Status](STATUS.md).

Warmor ships with advanced Rust-based WASM policy examples in the `policies/` directory. These demonstrate security enforcement patterns compiled to WebAssembly and evaluated by the daemon in userspace.

## Directory Layout

```
policies/
  advanced/           # Basic process/file policy (evaluate_syscall ABI)
  cross-platform/     # Platform-aware flat struct + C FFI ABI
  multi/              # Tagged enum dispatch (evaluate_event ABI)
  container-escape/   # Container breakout detection
  supply-chain/       # Runtime supply chain integrity
  temporal-access/    # Time-based access control
  zero-trust-net/     # Zero-trust network microsegmentation
  lateral-movement/   # Lateral movement detection
  crypto-mining/      # Cryptojacking detection
```

## ABI Patterns

All policies compile to `wasm32-unknown-unknown` with `crate-type = ["cdylib"]` and export `malloc`/`free` for host memory management.

### Pattern 1: Tagged Enum (Multi-Event)

Used by: `multi/`, `container-escape/`, `supply-chain/`, `lateral-movement/`, `crypto-mining/`

```rust
#[derive(Deserialize)]
#[serde(tag = "type")]
enum Event {
    #[serde(rename = "PROCESS")]
    Process(ProcessEvent),
    #[serde(rename = "FILE")]
    File(FileEvent),
    #[serde(rename = "NETWORK")]
    Network(NetworkEvent),
}

#[no_mangle]
pub extern "C" fn evaluate_event(event_ptr: *const u8, event_len: usize) -> i32
```

The host passes a JSON byte slice with a `"type"` discriminator. The policy deserializes into the appropriate variant and evaluates.

### Pattern 2: Cross-Platform (Flat Struct + C FFI)

Used by: `cross-platform/`, `temporal-access/`, `zero-trust-net/`

```rust
#[derive(Deserialize)]
struct Event {
    #[serde(rename = "type")]
    event_type: String,
    // ... all fields flat
}

#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32

#[no_mangle]
pub extern "C" fn evaluate(event_json: *const c_char) -> *mut c_char

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char)
```

Exports both the byte-slice ABI and a C-string ABI for cross-language compatibility. Returns a JSON `Decision` struct with action and reason fields.

### ABI Version

All advanced policies export `abi_version() -> u32` returning `2`, signaling support for the multi-event format and extended fields.

## Policy Descriptions

### Container Escape Detection (`container-escape/`)

Detects and blocks container breakout techniques:

- **Namespace manipulation**: `nsenter`, `unshare` execution from containers
- **Privilege escalation**: setuid binaries, `sudo` in container context
- **Ptrace attacks**: debugger attachment across cgroup boundaries
- **Docker socket access**: `/var/run/docker.sock` from containerized processes
- **Procfs namespace access**: `/proc/*/ns/*` traversal
- **Dangerous sysfs writes**: `core_pattern`, `modprobe` path manipulation
- **Host filesystem mounts**: bind mounts escaping container rootfs
- **Cloud metadata SSRF**: `169.254.169.254` access attempts
- **Kubernetes API pivots**: service account token abuse
- **Container runtime ports**: direct access to containerd/CRI-O sockets

### Supply Chain Integrity (`supply-chain/`)

Enforces runtime supply chain security:

- **Binary allowlist**: only pre-approved executables run in production
- **Package manager blocking**: no `apt`, `pip`, `npm` at runtime
- **Compiler blocking**: no `gcc`, `rustc`, `make` in production containers
- **Curl-pipe-bash detection**: blocks execution from `/dev/stdin`
- **Typosquatting detection**: flags suspiciously-named binaries
- **Library path protection**: blocks `.so` writes to system lib dirs
- **CA certificate tampering**: blocks modification of trust stores
- **Registry allowlisting**: only known registries on port 443
- **LD_PRELOAD protection**: blocks `ld.so.preload` and `ld.so.conf` writes

### Temporal Access Control (`temporal-access/`)

Time-based policy enforcement:

- **Startup-only binaries**: init processes (`tini`, `dumb-init`) allowed only in first 60s
- **Maintenance windows**: package managers and dump tools require maintenance flag
- **Business hours**: SSH/SCP restricted to Mon-Fri 08:00-18:00
- **Cron windows**: cron execution only during 02:00-04:00 and 06:00-07:00
- **Post-stabilization blocking**: no new binaries from `/tmp` after 5 minutes
- **Config freeze**: no `/etc` writes after startup period
- **Backup time restrictions**: `.bak`/`.dump` files only during backup window
- **Network initialization delay**: block non-DNS outbound in first 5 seconds

### Zero-Trust Network (`zero-trust-net/`)

Microsegmentation and network zero-trust enforcement:

- **Egress port allowlist**: only declared ports (53, 80, 443, DB ports, message queues)
- **Ingress port allowlist**: only declared service ports (8080, 8443, 9090, 3000)
- **Metadata IP blocking**: `169.254.169.254` and broadcast addresses denied
- **DNS resolver pinning**: only approved resolvers (CoreDNS, Docker DNS)
- **Network tool blocking**: `nc`, `nmap`, `tcpdump`, `socat` denied
- **IP manipulation blocking**: `ip` command execution denied
- **Network config protection**: `/etc/resolv.conf`, `/etc/hosts` immutable
- **Firewall rule protection**: iptables/nftables config files immutable
- **TLS key access control**: private keys require root access
- **Pod-to-pod restriction**: internal traffic only on declared dependency ports

### Lateral Movement Detection (`lateral-movement/`)

Detects and blocks lateral movement techniques:

- **Credential harvesting**: `mimikatz`, `impacket-*`, `lazagne`, `crackmapexec`
- **Network discovery**: `nmap`, `masscan`, `enum4linux`, `ldapsearch`
- **Tunneling/pivoting**: `chisel`, `socat`, `proxychains`, `ligolo`
- **Remote access tools**: `ssh`, `telnet`, `rsh`, `rlogin`
- **Lateral movement ports**: SSH, SMB, RDP, WinRM, NFS blocked outbound
- **Credential file access**: `/etc/shadow`, kerberos keytabs, SSH keys
- **Kubernetes config theft**: `.kube/config` access logged
- **C2 port blocking**: common C2 ports (4444, 5555, 1337, 31337)
- **SOCKS proxy blocking**: ports 1080, 9050 (Tor)
- **Pass-the-hash detection**: kerberos tool execution logged

### Crypto Mining Detection (`crypto-mining/`)

Detects and blocks cryptocurrency mining:

- **Known miner binaries**: 25+ miner names (xmrig, ccminer, ethminer, etc.)
- **Miner paths**: `/tmp/xmrig`, `/dev/shm/miner`, `/tmp/kinsing`
- **Mining pool ports**: Stratum (3333-3340), Bitcoin (8332-8333), Monero (45560-45700)
- **Pool domain blocking**: minergate, nanopool, 2miners, ethermine, f2pool, etc.
- **Stratum protocol detection**: `stratum+tcp://` and mining algorithm arguments
- **Wallet address detection**: Monero (95-char) and Bitcoin address patterns
- **Process disguise detection**: kernel thread names from suspicious paths
- **High-CPU alerting**: >80% CPU from temp directories
- **Cryptojacking malware**: kinsing, kdevtmpfsi, kthreaddi
- **System tuning abuse**: CPU governor, hugepages, MSR register access
- **Persistence blocking**: cron writes logged, executable writes to /tmp denied
- **IRC/Tor blocking**: common botnet C2 and anonymization channels

## Building

Each policy is an independent Rust crate. Build with:

```bash
rustup target add wasm32-unknown-unknown
cd policies/<name>
cargo build --release --target wasm32-unknown-unknown
```

The output WASM file will be at `target/wasm32-unknown-unknown/release/<crate_name>.wasm`.

All crates use an optimized release profile:

```toml
[profile.release]
opt-level = "z"      # Minimize binary size
lto = true           # Link-time optimization
codegen-units = 1    # Single codegen unit for better optimization
strip = true         # Strip debug symbols
```

## Return Values

All policies use the same action constants:

| Constant | Value | Meaning |
|----------|-------|---------|
| `ACTION_ALLOW` | 0 | Allow the operation |
| `ACTION_DENY` | 1 | Deny: the daemon kills the process (`SIGKILL`). Exec/connect denies are also cached in the kernel map, and with `--lsm-enforce` repeats get `EPERM`. |
| `ACTION_LOG` | 2 | Allow but emit an audit log entry |

## Writing Your Own

1. Create a new Rust crate with `cargo init --lib`
2. Set `crate-type = ["cdylib"]` in `Cargo.toml`
3. Add `serde`, `serde_json` dependencies
4. Export `malloc`, `free`, and one of `evaluate_syscall`/`evaluate_event`/`evaluate`
5. Optionally export `abi_version() -> u32` (return 2 for multi-event support)
6. Build with `cargo build --release --target wasm32-unknown-unknown`
7. Load with `warmor-daemon --policy path/to/policy.wasm`
