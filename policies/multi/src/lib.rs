use serde::Deserialize;
use std::slice;

// Event types matching Go EventType
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
    operation: String,
    protocol: String,
    remote_addr: String,
    remote_port: u16,
}

// Action constants
const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

// Sensitive file paths
const SENSITIVE_FILES: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh",
];

// Suspicious network ports
const SUSPICIOUS_PORTS: &[u16] = &[
    22,   // SSH
    23,   // Telnet
    3389, // RDP
    4444, // Metasploit
    5900, // VNC
];

// Blocked executables
const BLOCKED_BINARIES: &[&str] = &[
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/socat",
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
    // Rule 1: Block root from running bash
    if event.uid == 0 && event.filename.contains("bash") {
        return ACTION_DENY;
    }
    
    // Rule 2: Block execution from /tmp
    if event.filename.starts_with("/tmp/") {
        return ACTION_DENY;
    }
    
    // Rule 3: Block execution from Downloads
    if event.filename.contains("/Downloads/") || event.filename.contains("/downloads/") {
        return ACTION_DENY;
    }
    
    // Rule 4: Block network tools for non-root
    if event.uid != 0 {
        for blocked in BLOCKED_BINARIES {
            if event.filename.contains(blocked) {
                return ACTION_DENY;
            }
        }
    }
    
    // Rule 5: Log all Python executions
    if event.filename.contains("python") {
        return ACTION_LOG;
    }
    
    ACTION_ALLOW
}

fn evaluate_file(event: &FileEvent) -> i32 {
    // Rule 1: Log access to sensitive files
    for sensitive in SENSITIVE_FILES {
        if event.path.starts_with(sensitive) {
            return ACTION_LOG;
        }
    }
    
    // Rule 2: Block writes to /etc by non-root
    if event.uid != 0 && event.path.starts_with("/etc/") {
        // Check if it's a write operation (O_WRONLY=1, O_RDWR=2)
        if (event.flags & 0x3) != 0 {
            return ACTION_DENY;
        }
    }
    
    // Rule 3: Block access to other users' home directories
    if event.path.starts_with("/home/") {
        // Extract username from path
        let parts: Vec<&str> = event.path.split('/').collect();
        if parts.len() >= 3 {
            let _target_user = parts[2];
            // This is a simplified check - in production, map UID to username
            if event.uid >= 1000 && !event.path.contains(&format!("/home/{}", event.uid)) {
                return ACTION_DENY;
            }
        }
    }
    
    // Rule 4: Log all file operations in /var/log
    if event.path.starts_with("/var/log/") {
        return ACTION_LOG;
    }
    
    ACTION_ALLOW
}

fn evaluate_network(event: &NetworkEvent) -> i32 {
    // Rule 1: Block connections to suspicious ports for non-root
    if event.uid != 0 && SUSPICIOUS_PORTS.contains(&event.remote_port) {
        return ACTION_DENY;
    }
    
    // Rule 2: Log all outbound connections
    if event.operation == "connect" {
        return ACTION_LOG;
    }
    
    // Rule 3: Block connections to localhost from non-root
    if event.uid != 0 && (event.remote_addr == "127.0.0.1" || event.remote_addr == "::1") {
        // Allow common ports
        let allowed_local_ports = [80, 443, 8080, 3000, 5000];
        if !allowed_local_ports.contains(&event.remote_port) {
            return ACTION_DENY;
        }
    }
    
    // Rule 4: Block connections to private IP ranges from untrusted processes
    if event.uid >= 1000 {
        if event.remote_addr.starts_with("10.") ||
           event.remote_addr.starts_with("172.16.") ||
           event.remote_addr.starts_with("192.168.") {
            // Log for audit
            return ACTION_LOG;
        }
    }
    
    ACTION_ALLOW
}


