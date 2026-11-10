//! SHLWAPI path/string helpers, exported through shlwapi.dll forwarders.
//! These APIs use MAX_PATH-sized caller buffers, as documented by legacy
//! Shell Lightweight Utilities. Long-path APIs belong in PathCch instead.
use crate::{Bool, util::wstr};

#[inline]
fn sep(c: u16) -> bool { c == b'\\' as u16 || c == b'/' as u16 }
#[inline]
fn fold(c: u16) -> u16 { if (b'A' as u16..=b'Z' as u16).contains(&c) { c + 32 } else { c } }

/// Case-insensitive wildcard matching for ? and *. A semicolon is a spec
/// separator. This handles the common Win32 file masks without allocating.
fn glob(text: &[u16], pattern: &[u16]) -> bool {
    if pattern.len() == 3 && pattern[0] == b'*' as u16 && pattern[1] == b'.' as u16 && pattern[2] == b'*' as u16 { return true; }
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star, mut retry) = (None, 0usize);
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' as u16 || fold(pattern[pi]) == fold(text[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' as u16 {
            star = Some(pi);
            pi += 1;
            retry = ti;
        } else if let Some(s) = star {
            pi = s + 1;
            retry += 1;
            ti = retry;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' as u16 { pi += 1; }
    pi == pattern.len()
}

#[no_mangle]
pub unsafe extern "system" fn PathMatchSpecW(path: *const u16, spec: *const u16) -> Bool {
    if path.is_null() || spec.is_null() { return 0; }
    let text = unsafe { wstr(path) };
    let masks = unsafe { wstr(spec) };
    for mask in masks.split(|&c| c == b';' as u16) {
        let pat = mask.iter().copied().skip_while(|&c| c == b' ' as u16).collect::<SmallPattern>();
        if glob(text, pat.as_slice()) { return 1; }
    }
    0
}

// Non-allocating small pattern storage. Separate to keep kernel32 `no_std`.
struct SmallPattern { buffer: [u16; 1024], len: usize }
impl SmallPattern {
    fn new() -> Self { Self { buffer: [0; 1024], len: 0 } }
    fn as_slice(&self) -> &[u16] { &self.buffer[..self.len] }
}
impl core::iter::FromIterator<u16> for SmallPattern {
    fn from_iter<I: IntoIterator<Item=u16>>(items: I) -> Self {
        let mut result = Self::new();
        for c in items { if result.len < result.buffer.len() { result.buffer[result.len] = c; result.len += 1; } }
        result
    }
}

#[no_mangle]
pub unsafe extern "system" fn PathStripPathW(path: *mut u16) {
    if path.is_null() { return; }
    let text = unsafe { wstr(path) };
    let begin = text.iter().rposition(|&c| sep(c) || c == b':' as u16).map_or(0, |i| i + 1);
    let count = text.len() - begin;
    unsafe { core::ptr::copy(path.add(begin), path, count); *path.add(count) = 0; }
}

#[no_mangle]
pub unsafe extern "system" fn PathUnquoteSpacesW(path: *mut u16) {
    if path.is_null() { return; }
    let s = unsafe { wstr(path) };
    if s.len() < 2 || s[0] != b'"' as u16 || s[s.len()-1] != b'"' as u16 { return; }
    unsafe { core::ptr::copy(path.add(1), path, s.len()-2); *path.add(s.len()-2) = 0; }
}

#[no_mangle]
pub unsafe extern "system" fn PathQuoteSpacesW(path: *mut u16) {
    if path.is_null() { return; }
    let s = unsafe { wstr(path) };
    if s.is_empty() || s[0] == b'"' as u16 || !s.iter().any(|c| *c == b' ' as u16) { return; }
    if s.len() > 257 { return; }
    unsafe {
        core::ptr::copy(path, path.add(1), s.len());
        *path = b'"' as u16;
        *path.add(s.len()+1) = b'"' as u16;
        *path.add(s.len()+2) = 0;
    }
}

/// True only for exactly \\server\share (optionally with trailing slash).
#[no_mangle]
pub unsafe extern "system" fn PathIsUNCServerShareW(path: *const u16) -> Bool {
    if path.is_null() { return 0; }
    let s = unsafe { wstr(path) };
    if s.len() < 5 || !sep(s[0]) || !sep(s[1]) { return 0; }
    let Some(server_end) = s[2..].iter().position(|&c| sep(c)).map(|p| p + 2) else { return 0; };
    if server_end == 2 || server_end+1 >= s.len() { return 0; }
    let tail = &s[server_end+1..];
    (tail.iter().position(|&c| sep(c)).map_or(true, |p| p == tail.len()-1)) as Bool
}

/// Cut down to the root of a local drive or a UNC share.
#[no_mangle]
pub unsafe extern "system" fn PathStripToRootW(path: *mut u16) -> Bool {
    if path.is_null() { return 0; }
    let s = unsafe { wstr(path) };
    if s.len() >= 3 && s[1] == b':' as u16 && sep(s[2]) {
        unsafe { *path.add(3) = 0; }
        return 1;
    }
    if s.len() >= 2 && sep(s[0]) && sep(s[1]) {
        let Some(server_end) = s[2..].iter().position(|&c| sep(c)).map(|n| n+2) else { return 0; };
        let share_start = server_end+1;
        if share_start >= s.len() { return 0; }
        let share_end = s[share_start..].iter().position(|&c| sep(c)).map_or(s.len(), |n| n + share_start);
        if share_end == share_start { return 0; }
        unsafe { *path.add(share_end) = 0; }
        return 1;
    }
    0
}

/// Basic path canonicalisation for local and UNC paths; handles '.' and '..',
/// repeated separators, and MAX_PATH bounds. It preserves a relative path.
#[no_mangle]
pub unsafe extern "system" fn PathCanonicalizeW(out: *mut u16, input: *const u16) -> Bool {
    if out.is_null() || input.is_null() { return 0; }
    let original = unsafe { wstr(input) };
    if original.len() >= 260 { return 0; }
    let mut temp = [0u16; 260];
    let mut len = 0usize;
    let mut pos = 0usize;
    let mut root = 0usize;
    if original.len() >= 2 && original[1] == b':' as u16 {
        temp[0] = original[0]; temp[1] = b':' as u16;
        len = 2; pos = 2; root = 2;
        if pos < original.len() && sep(original[pos]) { temp[2] = b'\\' as u16; len = 3; root = 3; pos += 1; }
    } else if !original.is_empty() && sep(original[0]) {
        temp[0] = b'\\' as u16; len = 1; root = 1; pos = 1;
        if original.len() > 1 && sep(original[1]) {
            temp[1] = b'\\' as u16; len = 2; root = 2; pos = 2;
        }
    }
    while pos < original.len() {
        while pos < original.len() && sep(original[pos]) { pos += 1; }
        if pos == original.len() { break; }
        let start = pos;
        while pos < original.len() && !sep(original[pos]) { pos += 1; }
        let component = &original[start..pos];
        if component == [b'.' as u16] { continue; }
        if component == [b'.' as u16, b'.' as u16] {
            if len > root {
                while len > root && temp[len-1] != b'\\' as u16 { len -= 1; }
                if len > root { len -= 1; }
            }
            continue;
        }
        if len > 0 && temp[len-1] != b'\\' as u16 && !(len == 2 && temp[1] == b':' as u16) {
            if len >= temp.len()-1 { return 0; }
            temp[len] = b'\\' as u16; len += 1;
        }
        if len + component.len() >= temp.len() { return 0; }
        temp[len..len+component.len()].copy_from_slice(component);
        len += component.len();
    }
    if len == 0 { temp[0] = b'.' as u16; len = 1; }
    temp[len] = 0;
    unsafe { core::ptr::copy(temp.as_ptr(), out, len+1); }
    1
}

#[no_mangle]
pub unsafe extern "system" fn PathCommonPrefixW(a: *const u16, b: *const u16, out: *mut u16) -> i32 {
    if a.is_null() || b.is_null() { return 0; }
    let (left, right) = unsafe { (wstr(a), wstr(b)) };
    let mut n = 0usize;
    while n < left.len() && n < right.len() && fold(left[n]) == fold(right[n]) { n += 1; }
    // Shell paths use a directory component boundary for the common prefix.
    if n < left.len() && n < right.len() {
        while n > 0 && !sep(left[n-1]) { n -= 1; }
    }
    if !out.is_null() {
        unsafe { core::ptr::copy(left.as_ptr(), out, n); *out.add(n) = 0; }
    }
    n as i32
}

/// Remove a final path component, respecting local-drive and UNC roots.
/// The caller supplies the capacity, including the NUL terminator.
#[no_mangle]
pub unsafe extern "system" fn PathCchRemoveFileSpec(path: *mut u16, cap: usize) -> i32 {
    const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
    const S_FALSE: i32 = 1;
    if path.is_null() || cap == 0 || cap > 32_768 { return E_INVALIDARG; }
    let mut n = 0;
    while n < cap && unsafe { *path.add(n) } != 0 { n += 1; }
    if n == cap { return E_INVALIDARG; }
    let units = unsafe { core::slice::from_raw_parts(path, n) };
    let root = if n >= 3 && units[1] == b':' as u16 && sep(units[2]) {
        3
    } else if n >= 2 && sep(units[0]) && sep(units[1]) {
        // UNC root: \\server\share (plus optional separator).
        let server = units[2..].iter().position(|&c| sep(c)).map(|x| x+2);
        match server {
            Some(end) if end+1 < n => units[end+1..].iter().position(|&c| sep(c)).map_or(n, |x| end+1+x),
            _ => n,
        }
    } else if n > 0 && sep(units[0]) { 1 } else { 0 };
    if n <= root { return S_FALSE; }
    // Skip trailing separators beyond the root, then find the parent.
    let mut end = n;
    while end > root && sep(units[end-1]) { end -= 1; }
    if end <= root {
        unsafe { *path.add(root) = 0; }
        return if root == n { S_FALSE } else { 0 };
    }
    let cut = (root..end).rev().find(|&i| sep(units[i]));
    let parent = match cut {
        Some(i) => if i < root { root } else { i.max(root) },
        None => root,
    };
    if parent == n { return S_FALSE; }
    unsafe { *path.add(parent) = 0; }
    0
}
