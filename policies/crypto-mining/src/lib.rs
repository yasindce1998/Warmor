use serde::Deserialize;
use std::slice;

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

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct ProcessEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
    args: Vec<String>,
    parent_comm: String,
    cpu_percent: f32,
}

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct FileEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    operation: String,
    path: String,
    flags: u32,
}

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct NetworkEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    protocol: String,
    remote_addr: String,
    remote_port: u16,
    bytes_sent: u64,
    bytes_recv: u64,
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

const KNOWN_MINERS: &[&str] = &[
    "xmrig",
    "xmr-stak",
    "ccminer",
    "cgminer",
    "bfgminer",
    "cpuminer",
    "cpuminer-multi",
    "minerd",
    "ethminer",
    "t-rex",
    "phoenixminer",
    "nbminer",
    "gminer",
    "lolminer",
    "teamredminer",
    "nanominer",
    "wildrig",
    "srbminer",
    "claymore",
    "nicehash",
    "minergate",
    "kryptex",
    "honeyminer",
    "multiminer",
];

const MINER_BINARY_PATHS: &[&str] = &[
    "/tmp/xmrig",
    "/tmp/.hidden/miner",
    "/dev/shm/miner",
    "/var/tmp/miner",
    "/tmp/kdevtmpfsi",
    "/tmp/kinsing",
    "/tmp/.X11-unix/",
    "/root/.cache/miner",
];

const MINING_POOL_PORTS: &[u16] = &[
    3333,  // Stratum
    4444,  // Stratum alt
    5555,  // Stratum alt
    7777,  // Stratum alt
    8332,  // Bitcoin RPC
    8333,  // Bitcoin P2P
    9332,  // Litecoin RPC
    9333,  // Litecoin P2P
    14433, // Stratum TLS
    14444, // Stratum TLS alt
    45560, // Monero P2P
    45700, // Monero mining
    18080, // Monero RPC
    18081, // Monero restricted RPC
    30303, // Ethereum P2P
    8545,  // Ethereum JSON-RPC
    3334,  // Stratum V2
    4343,  // Nicehash
    2811,  // Mining proxy
];

const MINING_POOL_DOMAINS: &[&str] = &[
    "pool.minergate.com",
    "xmr.pool.minergate.com",
    "stratum.slushpool.com",
    "us-east.stratum.slushpool.com",
    "pool.supportxmr.com",
    "mine.moneropool.com",
    "pool.hashvault.pro",
    "monerohash.com",
    "minexmr.com",
    "nanopool.org",
    "xmr-eu1.nanopool.org",
    "herominers.com",
    "2miners.com",
    "ethermine.org",
    "f2pool.com",
    "antpool.com",
    "viabtc.com",
    "nicehash.com",
    "unmineable.com",
    "zergpool.com",
    "prohashing.com",
];

const STRATUM_INDICATORS: &[&str] = &[
    "stratum+tcp://",
    "stratum+ssl://",
    "stratum2+tcp://",
    "--url=stratum",
    "--algo=",
    "--coin=",
    "--donate-level",
    "-o stratum",
    "--threads=",
    "-t ",
    "--cpu-priority",
    "--randomx",
    "--cryptonight",
    "--kawpow",
    "--ethash",
    "--autolykos",
];

const CRYPTO_CONFIG_FILES: &[&str] = &[
    "config.json",
    "pools.txt",
    "miner.conf",
    "xmrig.json",
    "config_background.json",
    "cpu.txt",
    "gpu.txt",
];

#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut u8, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}

#[no_mangle]
pub extern "C" fn abi_version() -> u32 {
    2
}

#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };

    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY,
    };

    match event {
        Event::Process(e) => evaluate_process(&e),
        Event::File(e) => evaluate_file(&e),
        Event::Network(e) => evaluate_network(&e),
    }
}

fn evaluate_process(event: &ProcessEvent) -> i32 {
    let comm_lower = event.comm.to_lowercase();
    let filename_lower = event.filename.to_lowercase();

    // Block known miner process names
    for miner in KNOWN_MINERS {
        if comm_lower == *miner || comm_lower.contains(miner) {
            return ACTION_DENY;
        }
        if filename_lower.contains(miner) {
            return ACTION_DENY;
        }
    }

    // Block known miner binary paths
    for path in MINER_BINARY_PATHS {
        if event.filename.starts_with(path) {
            return ACTION_DENY;
        }
    }

    // Detect mining arguments in command line
    for arg in &event.args {
        let arg_lower = arg.to_lowercase();
        for indicator in STRATUM_INDICATORS {
            if arg_lower.contains(indicator) {
                return ACTION_DENY;
            }
        }

        // Detect wallet address patterns (long hex strings or addresses with pool prefix)
        if arg.len() > 90 && arg.chars().all(|c| c.is_ascii_hexdigit()) {
            return ACTION_DENY;
        }
        // Monero addresses start with 4 and are 95 chars
        if arg.len() == 95 && arg.starts_with('4') {
            return ACTION_DENY;
        }
        // Bitcoin addresses (P2PKH start with 1, P2SH with 3, Bech32 with bc1)
        if (arg.starts_with("bc1") || arg.starts_with('1') || arg.starts_with('3'))
            && arg.len() >= 26
            && arg.len() <= 62
            && arg.chars().all(|c| c.is_alphanumeric())
        {
            return ACTION_LOG;
        }
    }

    // Detect process disguise (miner renamed to look like system process)
    let disguised_names = ["kworker", "kthread", "ksoftirqd", "migration", "watchdog"];
    for name in &disguised_names {
        if event.comm.starts_with(name) && !event.filename.starts_with("/usr/") {
            if event.filename.starts_with("/tmp/")
                || event.filename.starts_with("/dev/shm/")
                || event.filename.starts_with("/var/tmp/")
            {
                return ACTION_DENY;
            }
        }
    }

    // Log high CPU processes from suspicious paths (crypto mining indicator)
    if event.cpu_percent > 80.0 {
        if event.filename.starts_with("/tmp/")
            || event.filename.starts_with("/dev/shm/")
            || event.filename.starts_with("/var/tmp/")
            || event.filename.starts_with("/root/")
        {
            return ACTION_LOG;
        }
    }

    // Block kinsing and kdevtmpfsi (common cryptojacking malware)
    let cryptojack_malware = ["kinsing", "kdevtmpfsi", "kthreaddi", "dbused", "solrd", "ld-musl"];
    for malware in &cryptojack_malware {
        if event.comm.contains(malware) || event.filename.contains(malware) {
            return ACTION_DENY;
        }
    }

    ACTION_ALLOW
}

fn evaluate_file(event: &FileEvent) -> i32 {
    let path_lower = event.path.to_lowercase();

    // Block creation of known miner config files in writable directories
    for config_file in CRYPTO_CONFIG_FILES {
        if event.path.ends_with(config_file) {
            if event.operation == "write" {
                // Only flag if in suspicious locations
                if event.path.starts_with("/tmp/")
                    || event.path.starts_with("/dev/shm/")
                    || event.path.starts_with("/var/tmp/")
                    || event.path.contains("/.cache/")
                    || event.path.contains("/.local/")
                {
                    return ACTION_DENY;
                }
            }
        }
    }

    // Block writing executable files to temp directories
    if event.operation == "write" && (event.flags & 0o111 != 0) {
        if event.path.starts_with("/tmp/")
            || event.path.starts_with("/dev/shm/")
            || event.path.starts_with("/var/tmp/")
        {
            return ACTION_DENY;
        }
    }

    // Detect miner downloads (common filenames)
    for miner in KNOWN_MINERS {
        if path_lower.contains(miner) && event.operation == "write" {
            return ACTION_DENY;
        }
    }

    // Block modification of CPU governor (miners often set to performance)
    if event.path.starts_with("/sys/devices/system/cpu/") && event.path.contains("scaling_governor") {
        return ACTION_DENY;
    }

    // Block modification of hugepages (XMRig uses hugepages for performance)
    if event.path == "/proc/sys/vm/nr_hugepages"
        || event.path == "/sys/kernel/mm/transparent_hugepage/enabled"
    {
        if event.operation == "write" {
            return ACTION_DENY;
        }
    }

    // Block writing to cron (miners install persistence via cron)
    if event.operation == "write" {
        if event.path.starts_with("/var/spool/cron/")
            || event.path.starts_with("/etc/cron.")
            || event.path == "/etc/crontab"
        {
            return ACTION_LOG;
        }
    }

    // Block modification of MSR registers (used by XMRig for performance)
    if event.path.starts_with("/dev/cpu/") && event.path.contains("/msr") {
        return ACTION_DENY;
    }

    ACTION_ALLOW
}

fn evaluate_network(event: &NetworkEvent) -> i32 {
    // Block connections to mining pool ports
    if MINING_POOL_PORTS.contains(&event.remote_port) {
        return ACTION_DENY;
    }

    // Block connections to known mining pool domains/IPs
    let addr_lower = event.remote_addr.to_lowercase();
    for pool in MINING_POOL_DOMAINS {
        if addr_lower.contains(pool) {
            return ACTION_DENY;
        }
    }

    // Detect Stratum protocol patterns (TCP connections to port 3333-3334 family)
    if event.remote_port >= 3333 && event.remote_port <= 3340 {
        return ACTION_DENY;
    }

    // Block IRC (sometimes used for mining pool coordination/botnet C2)
    if event.remote_port == 6667 || event.remote_port == 6668 || event.remote_port == 6697 {
        return ACTION_DENY;
    }

    // Log suspicious long-lived connections with high traffic (mining sessions)
    if event.bytes_sent > 0 && event.bytes_recv > 1_000_000 {
        if event.remote_port == 443 || event.remote_port == 80 {
            return ACTION_LOG;
        }
    }

    // Block Tor connections (miners sometimes route through Tor)
    let tor_ports: &[u16] = &[9050, 9051, 9150, 9151];
    if tor_ports.contains(&event.remote_port) {
        return ACTION_DENY;
    }

    // Block connections to residential proxy ranges often used by miners
    // (simplified: block connections to random high ports on non-standard IPs)
    if event.remote_port > 40000 && event.protocol == "tcp" {
        let is_internal = event.remote_addr.starts_with("10.")
            || event.remote_addr.starts_with("172.")
            || event.remote_addr.starts_with("192.168.");
        if !is_internal {
            return ACTION_LOG;
        }
    }

    ACTION_ALLOW
}
