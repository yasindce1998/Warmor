use std::alloc::{alloc, dealloc, Layout};
use std::slice;

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

/// Allocator shim — required by the warmor host ABI.
#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }
    unsafe { alloc(Layout::from_size_align(size, 1).unwrap()) }
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    unsafe { dealloc(ptr, Layout::from_size_align(size, 1).unwrap()) }
}

/// JSON-ABI entry point.
/// Policy: deny root running bash, log python, allow everything else.
#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    let bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    if let Ok(s) = std::str::from_utf8(bytes) {
        if s.contains("\"uid\":0") && s.contains("bash") {
            return ACTION_DENY;
        }
        if s.contains("python") {
            return ACTION_LOG;
        }
    }
    ACTION_ALLOW
}
