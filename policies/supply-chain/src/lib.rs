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
    parent_comm: String,
    args: Vec<String>,
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
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

const ALLOWED_BINARIES: &[&str] = &[
    "/usr/bin/nginx",
    "/usr/sbin/nginx",
    "/usr/local/bin/envoy",
    "/usr/bin/curl",
    "/usr/bin/tini",
    "/sbin/tini",
    "/usr/local/bin/dumb-init",
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/sleep",
    "/usr/bin/cat",
    "/usr/bin/grep",
    "/usr/bin/awk",
    "/usr/bin/sed",
];

const ALLOWED_LIBRARY_PATHS: &[&str] = &[
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/local/lib/",
];

const PACKAGE_MANAGERS: &[&str] = &[
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dpkg",
    "/usr/bin/yum",
    "/usr/bin/dnf",
    "/usr/bin/rpm",
    "/usr/bin/apk",
    "/usr/bin/pip",
    "/usr/bin/pip3",
    "/usr/local/bin/pip",
    "/usr/bin/npm",
    "/usr/local/bin/npm",
    "/usr/bin/gem",
    "/usr/local/bin/gem",
    "/usr/bin/cargo",
    "/usr/local/bin/cargo",
    "/usr/bin/go",
    "/usr/local/go/bin/go",
];

const COMPILER_TOOLS: &[&str] = &[
    "/usr/bin/gcc",
    "/usr/bin/g++",
    "/usr/bin/cc",
    "/usr/bin/make",
    "/usr/bin/cmake",
    "/usr/bin/ld",
    "/usr/bin/as",
    "/usr/bin/rustc",
    "/usr/local/bin/rustc",
];

const DOWNLOAD_TOOLS: &[&str] = &[
    "/usr/bin/wget",
    "/usr/bin/curl",
    "/usr/bin/fetch",
    "/usr/bin/aria2c",
    "/usr/bin/git",
    "/usr/bin/svn",
    "/usr/bin/scp",
    "/usr/bin/rsync",
];

const KNOWN_REGISTRIES: &[&str] = &[
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "rubygems.org",
    "crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "registry-1.docker.io",
    "ghcr.io",
    "quay.io",
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
    // Block package managers at runtime (packages should only be installed at build time)
    for pm in PACKAGE_MANAGERS {
        if event.filename == *pm {
            return ACTION_DENY;
        }
    }

    // Block compilers at runtime (no compilation in production)
    for compiler in COMPILER_TOOLS {
        if event.filename == *compiler {
            return ACTION_DENY;
        }
    }

    // Log download tools (potential supply chain injection)
    for dl_tool in DOWNLOAD_TOOLS {
        if event.filename == *dl_tool {
            // curl is allowed for health checks, but log it
            if event.filename.ends_with("curl") && event.parent_comm == "tini" {
                return ACTION_ALLOW;
            }
            return ACTION_LOG;
        }
    }

    // Binary allowlist enforcement: deny execution of unknown binaries
    if event.filename.starts_with("/") {
        let is_allowed = ALLOWED_BINARIES.iter().any(|b| event.filename == *b);
        let is_in_allowed_path = ALLOWED_LIBRARY_PATHS.iter().any(|p| event.filename.starts_with(p));

        if !is_allowed && !is_in_allowed_path {
            // Allow binaries in standard system paths but log them
            if event.filename.starts_with("/usr/bin/") || event.filename.starts_with("/usr/sbin/") {
                return ACTION_LOG;
            }
            // Deny binaries from non-standard paths
            if event.filename.starts_with("/tmp/")
                || event.filename.starts_with("/dev/shm/")
                || event.filename.starts_with("/var/tmp/")
                || event.filename.starts_with("/home/")
            {
                return ACTION_DENY;
            }
        }
    }

    // Block execution of scripts from pipes (curl | bash pattern)
    if event.filename == "/dev/stdin" || event.filename == "/proc/self/fd/0" {
        return ACTION_DENY;
    }

    // Detect typosquatting: log binaries with names similar to common tools
    let suspicious_names = ["pythom", "pythn", "nodee", "npmm", "curlx", "wgett"];
    for sus in &suspicious_names {
        if event.comm == *sus || event.filename.contains(sus) {
            return ACTION_DENY;
        }
    }

    ACTION_ALLOW
}

fn evaluate_file(event: &FileEvent) -> i32 {
    // Block modification of package manager databases
    let pkg_db_paths = [
        "/var/lib/dpkg/",
        "/var/lib/rpm/",
        "/var/lib/apt/",
        "/var/cache/apk/",
        "/etc/apk/",
    ];

    if event.operation == "write" || (event.flags & 0x3) != 0 {
        for db_path in &pkg_db_paths {
            if event.path.starts_with(db_path) {
                return ACTION_DENY;
            }
        }
    }

    // Block modification of shared libraries (LD_PRELOAD-style attacks)
    if event.operation == "write" || (event.flags & 0x3) != 0 {
        for lib_path in ALLOWED_LIBRARY_PATHS {
            if event.path.starts_with(lib_path) && event.path.ends_with(".so") {
                return ACTION_DENY;
            }
        }
        // Also block .so files with version suffixes
        if event.path.contains(".so.") {
            for lib_path in ALLOWED_LIBRARY_PATHS {
                if event.path.starts_with(lib_path) {
                    return ACTION_DENY;
                }
            }
        }
    }

    // Block modification of ld.so.preload and ld.so.conf
    if event.path == "/etc/ld.so.preload"
        || event.path == "/etc/ld.so.conf"
        || event.path.starts_with("/etc/ld.so.conf.d/")
    {
        if event.operation == "write" || (event.flags & 0x3) != 0 {
            return ACTION_DENY;
        }
    }

    // Block creation of setuid/setgid binaries
    if event.operation == "write" && (event.flags & 0o4000 != 0 || event.flags & 0o2000 != 0) {
        return ACTION_DENY;
    }

    // Block modification of CA certificates (MITM attacks)
    let cert_paths = ["/etc/ssl/certs/", "/usr/local/share/ca-certificates/", "/etc/pki/"];
    for cert_path in &cert_paths {
        if event.path.starts_with(cert_path) && (event.operation == "write" || (event.flags & 0x3) != 0) {
            return ACTION_DENY;
        }
    }

    // Log reads of sensitive package manager configs
    if event.operation == "read" {
        let sensitive_configs = ["/etc/pip.conf", "/root/.npmrc", "/root/.pypirc", "/root/.cargo/credentials"];
        for cfg in &sensitive_configs {
            if event.path == *cfg {
                return ACTION_LOG;
            }
        }
    }

    ACTION_ALLOW
}

fn evaluate_network(event: &NetworkEvent) -> i32 {
    // Block outbound connections on non-standard ports (C2 channels)
    let allowed_ports: &[u16] = &[53, 80, 443, 8080, 8443];
    if !allowed_ports.contains(&event.remote_port) {
        // Allow database ports for known apps
        let db_ports: &[u16] = &[3306, 5432, 6379, 27017, 9042];
        if db_ports.contains(&event.remote_port) {
            return ACTION_ALLOW;
        }
        return ACTION_DENY;
    }

    // Log connections to non-registry hosts on HTTPS (potential exfiltration)
    if event.remote_port == 443 {
        let is_known_registry = KNOWN_REGISTRIES.iter().any(|r| event.remote_addr.contains(r));
        if !is_known_registry {
            return ACTION_LOG;
        }
    }

    // Block raw socket usage (protocol != tcp && protocol != udp)
    if event.protocol != "tcp" && event.protocol != "udp" && event.protocol != "TCP" && event.protocol != "UDP" {
        return ACTION_DENY;
    }

    ACTION_ALLOW
}
