use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;

/// Event represents a security event from any platform. Field names match
/// the JSON the Warmor host sends to `evaluate_syscall`; every field is
/// optional because each event type only carries a subset of them.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
#[allow(dead_code)]
struct Event {
    /// "PROCESS", "FILE" or "NETWORK".
    #[serde(rename = "type")]
    event_type: String,
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    /// Executed binary (PROCESS).
    filename: String,
    args: Vec<String>,
    /// Target path (FILE).
    path: String,
    operation: String,
    flags: u32,
    /// Peer address and port (NETWORK).
    remote_addr: String,
    remote_port: u16,
    protocol: String,
}

impl Event {
    fn is(&self, kind: &str) -> bool {
        self.event_type.eq_ignore_ascii_case(kind)
    }
}

// Action constants matching Go
const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

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
    1  // Version 1 of the standardized ABI
}

#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    // Parse event from JSON
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    
    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY, // Deny on parse error
    };

    // Evaluate policy
    let decision = evaluate_policy(&event);
    
    // Convert decision to action code
    match decision.action.as_str() {
        "allow" => ACTION_ALLOW,
        "deny" => ACTION_DENY,
        "log" => ACTION_LOG,
        _ => ACTION_DENY,
    }
}


/// Decision represents the policy decision
#[derive(Debug, Serialize)]
struct Decision {
    action: String,
    reason: String,
}

impl Decision {
    fn allow(reason: &str) -> Self {
        Decision {
            action: "allow".to_string(),
            reason: reason.to_string(),
        }
    }

    fn deny(reason: &str) -> Self {
        Decision {
            action: "deny".to_string(),
            reason: reason.to_string(),
        }
    }

    fn log(reason: &str) -> Self {
        Decision {
            action: "log".to_string(),
            reason: reason.to_string(),
        }
    }
}

/// Cross-platform policy evaluation
fn evaluate_policy(event: &Event) -> Decision {
    // Rule 1: Block execution of dangerous binaries (cross-platform paths)
    let dangerous_binaries = [
        // Linux
        "/tmp/malware",
        "/tmp/suspicious",
        // Windows
        "C:\\Windows\\Temp\\malware.exe",
        "C:\\Temp\\suspicious.exe",
        // macOS
        "/tmp/malware",
        "/private/tmp/suspicious",
    ];

    for binary in &dangerous_binaries {
        if event.is("process") && event.filename.contains(binary) {
            return Decision::deny(&format!("Blocked dangerous binary: {}", binary));
        }
    }

    // Rule 2: Block execution from temp directories (platform-aware)
    if event.is("process") {
        let is_temp = event.filename.contains("/tmp/")
            || event.filename.contains("\\Temp\\")
            || event.filename.contains("\\AppData\\Local\\Temp\\")
            || event.filename.contains("/private/tmp/");

        if is_temp {
            return Decision::deny("Execution from temp directory blocked");
        }
    }

    // Rule 3: Monitor sensitive file access (cross-platform)
    if event.is("file") {
        let sensitive_paths = [
            // Linux
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh",
            // Windows
            "C:\\Windows\\System32\\config\\SAM",
            "\\.ssh\\",
            // macOS
            "/etc/master.passwd",
            "/var/root/.ssh",
        ];

        for path in &sensitive_paths {
            if event.path.contains(path) {
                return Decision::log(&format!("Sensitive file access: {}", path));
            }
        }
    }

    // Rule 4: Monitor network connections to suspicious ports
    if event.is("network") {
        let suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999];
        if suspicious_ports.contains(&event.remote_port) {
            return Decision::log(&format!(
                "Suspicious network connection to {}:{}",
                event.remote_addr, event.remote_port
            ));
        }
    }

    // Rule 5: Block root/admin execution of untrusted binaries
    if event.uid == 0 && event.is("process") {
        let untrusted_paths = [
            "/home/",
            "/Users/",
            "C:\\Users\\",
        ];

        for path in &untrusted_paths {
            if event.filename.contains(path) {
                return Decision::deny("Root/admin execution of user binary blocked");
            }
        }
    }

    // Rule 6: Monitor package manager execution (cross-platform)
    if event.is("process") {
        let package_managers = [
            "apt", "apt-get", "yum", "dnf",           // Linux
            "brew",                                    // macOS
            "choco", "winget", "scoop",               // Windows
        ];

        for pm in &package_managers {
            if event.comm.contains(pm) || event.filename.contains(pm) {
                return Decision::log(&format!("Package manager execution: {}", pm));
            }
        }
    }

    // Rule 7: Block execution with suspicious arguments
    if event.is("process") {
        let suspicious_args = [
            "curl", "wget", "powershell", "cmd.exe",
            "bash -c", "sh -c", "/bin/sh",
        ];

        for arg in &suspicious_args {
            for event_arg in &event.args {
                if event_arg.contains(arg) {
                    return Decision::log(&format!("Suspicious argument detected: {}", arg));
                }
            }
        }
    }

    // Default: allow
    Decision::allow("No policy violation")
}

/// WASM export: evaluate event
#[no_mangle]
pub extern "C" fn evaluate(event_json: *const c_char) -> *mut c_char {
    // Safety: Convert C string to Rust string
    let event_str = unsafe {
        if event_json.is_null() {
            return CString::new(r#"{"action":"deny","reason":"null event"}"#)
                .unwrap()
                .into_raw();
        }
        match CStr::from_ptr(event_json).to_str() {
            Ok(s) => s,
            Err(_) => {
                return CString::new(r#"{"action":"deny","reason":"invalid UTF-8"}"#)
                    .unwrap()
                    .into_raw()
            }
        }
    };

    // Parse event
    let event: Event = match serde_json::from_str(event_str) {
        Ok(e) => e,
        Err(err) => {
            let error_msg = format!(r#"{{"action":"deny","reason":"parse error: {}"}}"#, err);
            return CString::new(error_msg).unwrap().into_raw();
        }
    };

    // Evaluate policy
    let decision = evaluate_policy(&event);

    // Serialize decision
    let decision_json = match serde_json::to_string(&decision) {
        Ok(json) => json,
        Err(_) => r#"{"action":"deny","reason":"serialization error"}"#.to_string(),
    };

    // Return as C string
    CString::new(decision_json).unwrap().into_raw()
}

/// WASM export: free memory
#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if !s.is_null() {
            let _ = CString::from_raw(s);
        }
    }
}
