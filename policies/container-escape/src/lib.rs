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
    cgroup_id: u64,
    namespace_id: u64,
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
    cgroup_id: u64,
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
    cgroup_id: u64,
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

const ESCAPE_TOOLS: &[&str] = &[
    "/usr/bin/nsenter",
    "/usr/bin/unshare",
    "/usr/sbin/nsenter",
    "/usr/bin/chroot",
    "/usr/sbin/chroot",
    "/usr/bin/runc",
    "/usr/bin/ctr",
    "/usr/local/bin/crictl",
];

const NAMESPACE_PATHS: &[&str] = &[
    "/proc/1/ns/",
    "/proc/1/root",
    "/proc/1/cgroup",
    "/proc/self/ns/",
];

const DANGEROUS_MOUNTS: &[&str] = &[
    "/proc/sysrq-trigger",
    "/proc/sys/kernel/core_pattern",
    "/sys/kernel/",
    "/sys/fs/cgroup/",
];

const DOCKER_SOCKET_PATHS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/run/containerd/containerd.sock",
    "/var/run/crio/crio.sock",
];

const SENSITIVE_HOST_PATHS: &[&str] = &[
    "/host/",
    "/rootfs/",
    "/hostroot/",
    "/node/",
];

const PRIVILEGE_ESCALATION_BINARIES: &[&str] = &[
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/sbin/mount",
    "/usr/bin/capsh",
    "/usr/sbin/setcap",
    "/usr/bin/newuidmap",
    "/usr/bin/newgidmap",
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
    // Block namespace manipulation tools (nsenter, unshare)
    for tool in ESCAPE_TOOLS {
        if event.filename == *tool || event.filename.ends_with(tool.rsplit('/').next().unwrap_or("")) {
            return ACTION_DENY;
        }
    }

    // Block privilege escalation binaries inside containers
    for bin in PRIVILEGE_ESCALATION_BINARIES {
        if event.filename == *bin {
            return ACTION_DENY;
        }
    }

    // Block ptrace-based escapes (strace, ltrace, gdb attaching to host PID)
    let ptrace_tools = ["/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb", "/usr/bin/lldb"];
    for tool in &ptrace_tools {
        if event.filename == *tool {
            return ACTION_DENY;
        }
    }

    // Block container runtime exec (runc exec, ctr task exec)
    if event.comm == "runc" || event.comm == "ctr" || event.comm == "crictl" {
        return ACTION_DENY;
    }

    // Detect breakout via kernel exploit payloads executed from container writable paths
    let exploit_paths = ["/tmp/", "/dev/shm/", "/run/", "/var/tmp/"];
    for path in &exploit_paths {
        if event.filename.starts_with(path) && event.uid == 0 {
            return ACTION_DENY;
        }
    }

    // Log any process spawned by container runtimes (potential escape setup)
    let runtime_parents = ["containerd-shim", "runc", "crun", "youki"];
    for parent in &runtime_parents {
        if event.parent_comm == *parent && !event.filename.starts_with("/usr/") {
            return ACTION_LOG;
        }
    }

    ACTION_ALLOW
}

fn evaluate_file(event: &FileEvent) -> i32 {
    // Block access to Docker/containerd socket (container escape via socket)
    for sock in DOCKER_SOCKET_PATHS {
        if event.path == *sock || event.path.starts_with(sock) {
            return ACTION_DENY;
        }
    }

    // Block namespace file access (escape via setns)
    for ns_path in NAMESPACE_PATHS {
        if event.path.starts_with(ns_path) {
            return ACTION_DENY;
        }
    }

    // Block writes to dangerous procfs/sysfs paths
    if event.operation == "write" || (event.flags & 0x3) != 0 {
        for mount in DANGEROUS_MOUNTS {
            if event.path.starts_with(mount) {
                return ACTION_DENY;
            }
        }
    }

    // Block access to host filesystem via mounted paths
    for host_path in SENSITIVE_HOST_PATHS {
        if event.path.starts_with(host_path) {
            if event.operation == "write" || (event.flags & 0x3) != 0 {
                return ACTION_DENY;
            }
            return ACTION_LOG;
        }
    }

    // Block writing to /proc/*/exe (process replacement)
    if event.path.contains("/proc/") && event.path.ends_with("/exe") {
        return ACTION_DENY;
    }

    // Block core_pattern abuse (write to core_pattern triggers code as root)
    if event.path == "/proc/sys/kernel/core_pattern" {
        return ACTION_DENY;
    }

    // Block modprobe path manipulation
    if event.path == "/proc/sys/kernel/modprobe" {
        return ACTION_DENY;
    }

    // Log reading of container metadata
    let metadata_paths = ["/proc/self/cgroup", "/proc/1/cgroup", "/proc/self/mountinfo"];
    for meta in &metadata_paths {
        if event.path == *meta {
            return ACTION_LOG;
        }
    }

    ACTION_ALLOW
}

fn evaluate_network(event: &NetworkEvent) -> i32 {
    // Block connections to cloud metadata service (SSRF-based escape)
    if event.remote_addr == "169.254.169.254" {
        return ACTION_DENY;
    }

    // Block connections to Kubernetes API (potential cluster pivot)
    if event.remote_port == 6443 || event.remote_port == 10250 {
        return ACTION_DENY;
    }

    // Block connections to Docker daemon port
    if event.remote_port == 2375 || event.remote_port == 2376 {
        return ACTION_DENY;
    }

    // Log connections to other containers on internal bridge network
    if event.remote_addr.starts_with("172.17.") || event.remote_addr.starts_with("172.18.") {
        return ACTION_LOG;
    }

    ACTION_ALLOW
}
