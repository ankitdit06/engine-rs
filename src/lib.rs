use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::os::raw::c_char;
use std::slice;
use std::sync::{Arc, RwLock};
use std::{ffi::CStr, str};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use aho_corasick::AhoCorasick;
use serde::Deserialize;

// ---------- Data structures ----------

// One Aho–Corasick matcher per route_id
// route_id is a u32 (you decide how to map URIs -> route_id in Lua)
static ROUTE_ENGINES: Lazy<RwLock<HashMap<u32, Arc<AhoCorasick>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

// Optional: keep track of how many patterns per route (for debugging / metrics)
static ROUTE_PATTERN_COUNTS: Lazy<RwLock<HashMap<u32, usize>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Rules expected from control plane (after base64 decode) as JSON:
/// ["rm -rf", "DROP TABLE", "curl http"]
///
/// If you later want richer metadata (ids, severity, etc.), you can wrap this
/// in a struct and change the deserialization accordingly.
#[derive(Debug, Deserialize)]
struct RuleList(Vec<String>);

// ---------- Helpers ----------

fn decode_b64_json_patterns(blob: *const u8, len: usize) -> Result<Vec<String>, i32> {
    if blob.is_null() || len == 0 {
        return Err(-1);
    }

    // SAFETY: caller guarantees pointer+len is valid.
    let data = unsafe { slice::from_raw_parts(blob, len) };

    let b64_str = str::from_utf8(data).map_err(|_| -2)?;

    let decoded = STANDARD.decode(b64_str).map_err(|_| -2)?;

    // Expect plain JSON array of strings: ["pat1","pat2",...]
    let patterns: Vec<String> = serde_json::from_slice(&decoded).map_err(|_| -3)?;

    // Optional: enforce limits here to avoid abuse.
    // e.g.:
    // if patterns.len() > 10_000 { return Err(-3); }

    Ok(patterns)
}

// ---------- FFI: Rule loading per route ----------

/// Load rules for a specific route_id.
///
/// Lua/agent decides:
///   - which URI maps to which route_id (u32)
///   - what patterns are for each route_id
///
/// Input:
///   route_id: logical id of the route (e.g. 1,2,3...)
///   blob: pointer to base64(JSON array of strings)
///   len: length of that base64 string
///
/// Return codes:
///   0   = success
///  -1   = null pointer or zero length
///  -2   = invalid UTF-8 or base64
///  -3   = invalid JSON
///  -4   = failed to build Aho–Corasick automaton
#[no_mangle]
pub extern "C" fn engine_load_route_rules(route_id: u32, blob: *const u8, len: usize) -> i32 {
    let patterns = match decode_b64_json_patterns(blob, len) {
        Ok(p) => p,
        Err(code) => return code,
    };

    let ac = match AhoCorasick::new(&patterns) {
        Ok(ac) => ac,
        Err(_) => return -4,
    };

    {
        let mut engines = ROUTE_ENGINES.write().unwrap();
        engines.insert(route_id, Arc::new(ac));
    }

    {
        let mut counts = ROUTE_PATTERN_COUNTS.write().unwrap();
        counts.insert(route_id, patterns.len());
    }

    0
}

/// Clear rules for a specific route_id.
///
/// Returns:
///   0 = success (even if route_id was not present)
#[no_mangle]
pub extern "C" fn engine_clear_route_rules(route_id: u32) -> i32 {
    {
        let mut engines = ROUTE_ENGINES.write().unwrap();
        engines.remove(&route_id);
    }
    {
        let mut counts = ROUTE_PATTERN_COUNTS.write().unwrap();
        counts.remove(&route_id);
    }
    0
}

/// Clear ALL route rules.
///
/// Returns:
///   0 = success
#[no_mangle]
pub extern "C" fn engine_clear_all_rules() -> i32 {
    {
        let mut engines = ROUTE_ENGINES.write().unwrap();
        engines.clear();
    }
    {
        let mut counts = ROUTE_PATTERN_COUNTS.write().unwrap();
        counts.clear();
    }
    0
}

// ---------- FFI: Matching per route ----------

/// Check a response (C string) against rules for the given route_id.
///
/// Returns:
///   1 = at least one pattern matched for this route
///   0 = no match, route not configured, or invalid input
#[no_mangle]
pub extern "C" fn engine_check_response_for_route(
    route_id: u32,
    content: *const c_char,
) -> i32 {
    if content.is_null() {
        return 0;
    }

    // SAFETY: null-terminated C string
    let cstr = unsafe { CStr::from_ptr(content) };
    let text = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Clone Arc under read lock, then drop lock before matching
    let ac_opt: Option<Arc<AhoCorasick>> = {
        let engines = ROUTE_ENGINES.read().unwrap();
        engines.get(&route_id).cloned()
    };

    let ac = match ac_opt {
        Some(ac) => ac,
        None => return 0, // no rules for this route
    };

    if ac.is_match(text) {
        1
    } else {
        0
    }
}

// ---------- Backward-compatible global API (route_id = 0) ----------

/// Legacy: load global rules without route.
/// This just maps to route_id = 0.
#[no_mangle]
pub extern "C" fn engine_load_rules(blob: *const u8, len: usize) -> i32 {
    engine_load_route_rules(0, blob, len)
}

/// Legacy: check response against global rules (route_id = 0).
#[no_mangle]
pub extern "C" fn engine_check_response(content: *const c_char) -> i32 {
    engine_check_response_for_route(0, content)
}
