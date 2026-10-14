use serde::Deserialize;
use std::slice;

#[derive(Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct Event {
    /// "PROCESS", "FILE" or "NETWORK". Empty for legacy hosts that only
    /// sent process events.
    #[serde(rename = "type")]
    event_type: String,
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    /// Executed binary (PROCESS events).
    filename: String,
    /// Target path (FILE events).
    path: String,
}

// Action constants matching Go
const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

// Blocked executables for non-root users
const BLOCKED_BINARIES: &[&str] = &[
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/socat",
    "/usr/bin/netcat",
];

// Sensitive directories that require logging
const SENSITIVE_DIRS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh",
    "/home/",
];

// System binaries that should only be run by root
const ROOT_ONLY_BINARIES: &[&str] = &[
    "/usr/sbin/",
    "/sbin/",
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
    // Parse event from JSON
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    
    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY, // Deny on parse error
    };

    match event.event_type.as_str() {
        "" | "PROCESS" => evaluate_process(&event),
        "FILE" => evaluate_file(&event),
        _ => ACTION_ALLOW,
    }
}

fn evaluate_file(event: &Event) -> i32 {
    // Log access to sensitive files/directories
    for sensitive in SENSITIVE_DIRS {
        if event.path.starts_with(sensitive) {
            return ACTION_LOG;
        }
    }
    ACTION_ALLOW
}

fn evaluate_process(event: &Event) -> i32 {
    // Rule 1: Block network tools for non-root users
    if event.uid != 0 {
        for blocked in BLOCKED_BINARIES {
            if event.filename.contains(blocked) {
                return ACTION_DENY;
            }
        }
    }

    // Rule 2: Block non-root users from running system binaries
    if event.uid != 0 {
        for root_only in ROOT_ONLY_BINARIES {
            if event.filename.starts_with(root_only) {
                return ACTION_DENY;
            }
        }
    }

    // Rule 3: Log access to sensitive files/directories
    for sensitive in SENSITIVE_DIRS {
        if event.filename.starts_with(sensitive) {
            return ACTION_LOG;
        }
    }

    // Rule 4: Block root from running bash (example from Phase 1)
    if event.uid == 0 && event.filename.contains("bash") {
        return ACTION_DENY;
    }

    // Rule 5: Log all python executions
    if event.filename.contains("python") {
        return ACTION_LOG;
    }

    // Rule 6: Block execution from /tmp directory
    if event.filename.starts_with("/tmp/") {
        return ACTION_DENY;
    }

    // Rule 7: Block execution from user download directories
    if event.filename.contains("/Downloads/") || event.filename.contains("/downloads/") {
        return ACTION_DENY;
    }

    // Default: allow
    ACTION_ALLOW
}


