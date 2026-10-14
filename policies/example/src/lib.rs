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
    filename: String,
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
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    // Parse event from JSON
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    
    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY, // Deny on parse error
    };

    // The rules below are about executed binaries.
    if !(event.event_type.is_empty() || event.event_type == "PROCESS") {
        return ACTION_ALLOW;
    }

    // Example policy: Block root from running bash
    if event.uid == 0 && event.filename.contains("bash") {
        return ACTION_DENY;
    }

    // Example policy: Log all python executions
    if event.filename.contains("python") {
        return ACTION_LOG;
    }

    // Default: allow
    ACTION_ALLOW
}


