use once_cell::sync::Lazy;
use std::os::raw::c_char;
use std::slice;
use std::sync::{Arc, RwLock};
use std::{ffi::CStr, str};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use aho_corasick::AhoCorasick;

// Global Aho–Corasick automaton, shared by all workers/threads.
// We wrap it in Arc so readers can cheaply clone a handle and drop the lock.
static AC_AUTOMATON: Lazy<RwLock<Option<Arc<AhoCorasick>>>> =
    Lazy::new(|| RwLock::new(None));

/// Load rules into the engine.
///
/// Expects:
///   - `blob` = pointer to base64-encoded JSON array of strings
///   - e.g. JSON: ["rm -rf", "DROP TABLE", "llm-injection"]
///
/// Return codes:
///   0   = success
///  -1   = null pointer or zero length
///  -2   = invalid UTF-8 or base64
///  -3   = invalid JSON or wrong shape
///  -4   = failed to build Aho–Corasick automaton
#[no_mangle]
pub extern "C" fn engine_load_rules(blob: *const u8, len: usize) -> i32 {
    if blob.is_null() || len == 0 {
        return -1;
    }

    // SAFETY: caller promises `blob` points to `len` bytes.
    let data = unsafe { slice::from_raw_parts(blob, len) };

    // blob bytes must be valid UTF-8 base64 text
    let b64_str = match str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return -2,
    };

    // base64 decode → raw JSON bytes
    let decoded = match STANDARD.decode(b64_str) {
        Ok(bytes) => bytes,
        Err(_) => return -2,
    };

    // JSON must be: ["pattern1", "pattern2", ...]
    let patterns: Vec<String> = match serde_json::from_slice(&decoded) {
        Ok(v) => v,
        Err(_) => return -3,
    };

    // Optional: you can enforce limits here:
    // - max number of patterns
    // - max length per pattern
    // to protect against abusive rule payloads.

    // Build Aho–Corasick automaton
    let ac = match AhoCorasick::new(&patterns) {
        Ok(ac) => ac,
        Err(_) => return -4,
    };

    // Swap automaton atomically under write lock
    let mut guard = AC_AUTOMATON.write().unwrap();
    *guard = Some(Arc::new(ac));

    0
}

/// Check a C string response against all loaded patterns.
///
/// Returns:
///   1 = at least one pattern matched
///   0 = no match, invalid input, or no rules loaded
#[no_mangle]
pub extern "C" fn engine_check_response(content: *const c_char) -> i32 {
    if content.is_null() {
        return 0;
    }

    // SAFETY: `content` must be a valid null-terminated C string.
    let cstr = unsafe { CStr::from_ptr(content) };
    let text = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 0, // non-UTF-8 → treat as "no match"
    };

    // Grab current automaton under read lock, then clone Arc and drop lock
    let ac_arc_opt = {
        let guard = AC_AUTOMATON.read().unwrap();
        guard.clone()
    };

    let ac = match ac_arc_opt {
        Some(ac) => ac,
        None => return 0, // no rules loaded yet
    };

    if ac.is_match(text) {
        1
    } else {
        0
    }
}
