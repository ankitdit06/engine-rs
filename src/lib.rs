use once_cell::sync::Lazy;
use std::os::raw::c_char;
use std::slice;
use std::sync::RwLock;
use std::{ffi::CStr, str};

// IMPORTANT: Needed for base64::Engine trait
use base64::Engine;

static PATTERN: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));

#[no_mangle]
pub extern "C" fn engine_load_rules(blob: *const u8, len: usize) -> i32 {
    if blob.is_null() || len == 0 {
        return -1;
    }

    let data = unsafe { slice::from_raw_parts(blob, len) };

    let b64_str = match str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    // Correct API usage:
    let decoded = match base64::engine::general_purpose::STANDARD.decode(b64_str) {
        Ok(bytes) => bytes,
        Err(_) => return -2,
    };

    let pattern = match String::from_utf8(decoded) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let mut guard = PATTERN.write().unwrap();
    *guard = Some(pattern);
    0
}

#[no_mangle]
pub extern "C" fn engine_check_response(content: *const c_char) -> i32 {
    if content.is_null() {
        return 0;
    }

    let cstr = unsafe { CStr::from_ptr(content) };
    let text = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let guard = PATTERN.read().unwrap();
    if let Some(ref pat) = *guard {
        if !pat.is_empty() && text.contains(pat) {
            return 1;
        }
    }
    0
}
