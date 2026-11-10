//! COM and WinRT basics, and the shlwapi/shcore path and string helpers
//! programs import through API sets (api-ms-win-core-com, -winrt-*,
//! -shlwapi-legacy, api-ms-win-shcore-*), hosted here until combase,
//! shlwapi and shcore exist.
//!
//! COM initializes, allocates its task memory and makes GUIDs, but has no
//! classes registered: CoCreateInstance answers REGDB_E_CLASSNOTREG, and
//! programs take their fallbacks (a file dialog through GetOpenFileName,
//! say). WinRT likewise has strings but no activatable classes.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::util::{alloc, free, wstr};
use crate::{Bool, Handle};

type HResult = i32;
const S_OK: HResult = 0;
const S_FALSE: HResult = 1;
const E_NOTIMPL: HResult = 0x8000_4001u32 as i32;
const E_INVALIDARG: HResult = 0x8007_0057u32 as i32;
const E_OUTOFMEMORY: HResult = 0x8007_000Eu32 as i32;
const E_FAIL: HResult = 0x8000_4005u32 as i32;
const REGDB_E_CLASSNOTREG: HResult = 0x8004_0154u32 as i32;

// -----| COM |-----

// COM apartment mode and nesting depth are per-thread.  Store them in a
// kernel32 TLS slot so even callbacks crossing DLLs observe the same state.
// Low two bits: 1=STA, 2=MTA; remaining bits: CoInitialize count.
static COM_TLS_SLOT: AtomicU32 = AtomicU32::new(u32::MAX);
const COM_TLS_ALLOCATING: u32 = u32::MAX - 1;
const RPC_E_CHANGED_MODE: HResult = 0x8001_0106u32 as i32;
const CO_E_NOTINITIALIZED: HResult = 0x8004_01F0u32 as i32;

fn com_slot() -> Option<u32> {
    loop {
        let index = COM_TLS_SLOT.load(Ordering::Acquire);
        if index < COM_TLS_ALLOCATING { return Some(index); }
        if index == COM_TLS_ALLOCATING { core::hint::spin_loop(); continue; }
        if COM_TLS_SLOT.compare_exchange(u32::MAX, COM_TLS_ALLOCATING, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            let allocated = crate::sync::TlsAlloc();
            COM_TLS_SLOT.store(allocated, Ordering::Release);
            return if allocated == u32::MAX { None } else { Some(allocated) };
        }
    }
}

#[no_mangle]
pub extern "system" fn CoInitializeEx(reserved: usize, model: u32) -> HResult {
    // COINIT_APARTMENTTHREADED=2; 4 and 8 are optional flags, not modes.
    if reserved != 0 || model & !0xE != 0 { return E_INVALIDARG; }
    let mode = if model & 2 != 0 { 1usize } else { 2usize };
    let Some(index) = com_slot() else { return E_OUTOFMEMORY; };
    let value = crate::sync::TlsGetValue(index);
    if value == 0 {
        if crate::sync::TlsSetValue(index, 4 | mode) != 0 { S_OK } else { E_OUTOFMEMORY }
    } else if value & 3 != mode {
        RPC_E_CHANGED_MODE
    } else if value >> 2 == usize::MAX >> 2 {
        E_FAIL
    } else if crate::sync::TlsSetValue(index, value + 4) != 0 {
        S_FALSE
    } else {
        E_OUTOFMEMORY
    }
}

#[no_mangle]
pub extern "system" fn CoInitialize(reserved: usize) -> HResult {
    CoInitializeEx(reserved, 2)
}

#[no_mangle]
pub extern "system" fn OleInitialize(reserved: usize) -> HResult {
    CoInitializeEx(reserved, 2)
}

#[no_mangle]
pub extern "system" fn CoUninitialize() {
    // Do not allocate a TLS slot merely because an uninitialised thread
    // called CoUninitialize.
    let index = COM_TLS_SLOT.load(Ordering::Acquire);
    if index >= COM_TLS_ALLOCATING { return; }
    let value = crate::sync::TlsGetValue(index);
    if value >= 5 { let _ = crate::sync::TlsSetValue(index, if value < 9 { 0 } else { value - 4 }); }
}

#[no_mangle]
pub extern "system" fn OleUninitialize() {
    CoUninitialize();
}

/// OLE32: report the caller's actual COM apartment when it has one.
/// APTTYPE_STA=0; APTTYPE_MTA=1; APTTYPEQUALIFIER_NONE=0.
#[no_mangle]
pub unsafe extern "system" fn CoGetApartmentType(apartment: *mut i32, qualifier: *mut i32) -> HResult {
    if apartment.is_null() || qualifier.is_null() { return E_INVALIDARG; }
    let index = COM_TLS_SLOT.load(Ordering::Acquire);
    if index >= COM_TLS_ALLOCATING { return CO_E_NOTINITIALIZED; }
    let value = crate::sync::TlsGetValue(index);
    if value == 0 { return CO_E_NOTINITIALIZED; }
    unsafe {
        *apartment = if value & 3 == 1 { 0 } else { 1 };
        *qualifier = 0;
    }
    S_OK
}

#[no_mangle]
pub unsafe extern "system" fn CoCreateInstance(_clsid: *const u8, _outer: usize, _ctx: u32, _iid: *const u8, out: *mut usize) -> HResult {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    REGDB_E_CLASSNOTREG
}

#[no_mangle]
pub unsafe extern "system" fn CoGetClassObject(_clsid: *const u8, _ctx: u32, _info: usize, _iid: *const u8, out: *mut usize) -> HResult {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    REGDB_E_CLASSNOTREG
}

#[no_mangle]
pub extern "system" fn CoTaskMemAlloc(size: usize) -> *mut u8 {
    alloc(size.max(1))
}

#[no_mangle]
pub extern "system" fn CoTaskMemFree(p: *mut u8) {
    if !p.is_null() {
        free(p);
    }
}

#[no_mangle]
pub extern "system" fn CoTaskMemRealloc(p: *mut u8, size: usize) -> *mut u8 {
    if p.is_null() {
        return CoTaskMemAlloc(size);
    }
    crate::mem::HeapReAlloc(crate::util::process_heap() as Handle, 0, p, size.max(1))
}

static GUID_STATE: AtomicU64 = AtomicU64::new(0);

/// A version-4 GUID from a time-seeded generator.
#[no_mangle]
pub unsafe extern "system" fn CoCreateGuid(out: *mut [u8; 16]) -> HResult {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let next = || {
        let mut s = GUID_STATE.load(Ordering::Relaxed);
        if s == 0 {
            s = crate::time::GetTickCount64() ^ 0x9E37_79B9_7F4A_7C15;
        }
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        GUID_STATE.store(s, Ordering::Relaxed);
        s
    };
    let (a, b) = (next(), next());
    let mut g = [0u8; 16];
    g[..8].copy_from_slice(&a.to_le_bytes());
    g[8..].copy_from_slice(&b.to_le_bytes());
    g[7] = (g[7] & 0x0F) | 0x40;
    g[8] = (g[8] & 0x3F) | 0x80;
    unsafe { *out = g };
    S_OK
}

/// PROPVARIANT: its storage is freed (strings with CoTaskMemFree) and it
/// becomes VT_EMPTY.
#[no_mangle]
pub unsafe extern "system" fn PropVariantClear(pv: *mut u8) -> HResult {
    if pv.is_null() {
        return E_INVALIDARG;
    }
    let vt = unsafe { *(pv as *const u16) };
    if vt == 31 || vt == 30 {
        // VT_LPWSTR, VT_LPSTR
        CoTaskMemFree(unsafe { *(pv.add(8) as *const *mut u8) });
    }
    unsafe { core::ptr::write_bytes(pv, 0, 24) };
    S_OK
}

#[no_mangle]
pub unsafe extern "system" fn CoWaitForMultipleHandles(_flags: u32, ms: u32, n: u32, handles: *const Handle, index: *mut u32) -> HResult {
    let r = unsafe { crate::process::WaitForMultipleObjects(n, handles, 0, ms) };
    if !index.is_null() {
        unsafe { *index = r };
    }
    match r {
        0x102 => 0x8001_011Fu32 as i32, // RPC_S_CALLPENDING
        r if r < n => S_OK,
        _ => E_FAIL,
    }
}

#[no_mangle]
pub extern "system" fn CoCreateFreeThreadedMarshaler(_outer: usize, out: *mut usize) -> HResult {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    E_NOTIMPL
}

/// "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
#[no_mangle]
pub unsafe extern "system" fn StringFromGUID2(g: *const [u8; 16], out: *mut u16, cap: i32) -> i32 {
    if g.is_null() || out.is_null() || cap < 39 {
        return 0;
    }
    let g = unsafe { *g };
    let hex = b"0123456789ABCDEF";
    let mut s = [0u16; 39];
    let mut at = 0;
    let mut put = |c: u8| {
        s[at] = c as u16;
        at += 1;
    };
    put(b'{');
    let order: [usize; 16] = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    for (k, &i) in order.iter().enumerate() {
        if matches!(k, 4 | 6 | 8 | 10) {
            put(b'-');
        }
        put(hex[(g[i] >> 4) as usize]);
        put(hex[(g[i] & 15) as usize]);
    }
    put(b'}');
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), out, 39) };
    39
}

// -----| WinRT strings (HSTRING) |-----
//
// An HSTRING is a heap block: length (u32), then the text with a NUL. A
// "reference" string is the same, made by the caller's header buffer.

#[no_mangle]
pub unsafe extern "system" fn WindowsCreateString(s: *const u16, len: u32, out: *mut usize) -> HResult {
    if out.is_null() {
        return E_INVALIDARG;
    }
    if len == 0 {
        unsafe { *out = 0 };
        return S_OK;
    }
    let p = alloc(8 + (len as usize + 1) * 2);
    if p.is_null() {
        return E_OUTOFMEMORY;
    }
    unsafe {
        *(p as *mut u32) = len;
        core::ptr::copy_nonoverlapping(s, p.add(8) as *mut u16, len as usize);
        *(p.add(8) as *mut u16).add(len as usize) = 0;
        *out = p as usize;
    }
    S_OK
}

#[no_mangle]
pub unsafe extern "system" fn WindowsCreateStringReference(s: *const u16, len: u32, _header: *mut u8, out: *mut usize) -> HResult {
    // A real copy is as good (the header buffer is the caller's to keep).
    unsafe { WindowsCreateString(s, len, out) }
}

#[no_mangle]
pub extern "system" fn WindowsDeleteString(h: usize) -> HResult {
    if h != 0 {
        free(h as *mut u8);
    }
    S_OK
}

#[no_mangle]
pub unsafe extern "system" fn WindowsGetStringRawBuffer(h: usize, len: *mut u32) -> *const u16 {
    static EMPTY: u16 = 0;
    if h == 0 {
        if !len.is_null() {
            unsafe { *len = 0 };
        }
        return &EMPTY;
    }
    if !len.is_null() {
        unsafe { *len = *(h as *const u32) };
    }
    (h + 8) as *const u16
}

#[no_mangle]
pub extern "system" fn WindowsGetStringLen(h: usize) -> u32 {
    if h == 0 { 0 } else { unsafe { *(h as *const u32) } }
}

#[no_mangle]
pub extern "system" fn RoInitialize(kind: u32) -> HResult {
    match kind {
        0 => CoInitializeEx(0, 2), // RO_INIT_SINGLETHREADED (STA)
        1 => CoInitializeEx(0, 0), // RO_INIT_MULTITHREADED (MTA)
        _ => E_INVALIDARG,
    }
}

#[no_mangle]
pub extern "system" fn RoUninitialize() { CoUninitialize() }

/// No activatable classes.
#[no_mangle]
pub unsafe extern "system" fn RoGetActivationFactory(_class: usize, _iid: *const u8, out: *mut usize) -> HResult {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    REGDB_E_CLASSNOTREG
}

#[no_mangle]
pub unsafe extern "system" fn RoActivateInstance(_class: usize, out: *mut usize) -> HResult {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    REGDB_E_CLASSNOTREG
}

#[no_mangle]
pub extern "system" fn SetRestrictedErrorInfo(_info: usize) -> HResult {
    S_OK
}

#[no_mangle]
pub unsafe extern "system" fn GetRestrictedErrorInfo(out: *mut usize) -> HResult {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    S_FALSE
}

#[no_mangle]
pub unsafe extern "system" fn RoGetMatchingRestrictedErrorInfo(_hr: HResult, out: *mut usize) -> HResult {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    E_FAIL
}

#[no_mangle]
pub extern "system" fn RoOriginateError(_hr: HResult, _msg: usize) -> Bool {
    0
}

#[no_mangle]
pub extern "system" fn RoOriginateErrorW(_hr: HResult, _len: u32, _msg: *const u16) -> Bool {
    0
}

// -----| shlwapi / shcore helpers |-----

const BACKSLASH: u16 = b'\\' as u16;

fn is_sep(c: u16) -> bool {
    c == BACKSLASH || c == b'/' as u16
}

#[no_mangle]
pub unsafe extern "system" fn PathFileExistsW(p: *const u16) -> Bool {
    if p.is_null() {
        return 0;
    }
    (unsafe { crate::file::GetFileAttributesW(p) } != u32::MAX) as Bool
}

#[no_mangle]
pub unsafe extern "system" fn PathFileExistsA(p: *const u8) -> Bool {
    if p.is_null() {
        return 0;
    }
    let w = unsafe { crate::util::widen(p) };
    unsafe { PathFileExistsW(w.as_ptr()) }
}

/// No ':' or path separator.
#[no_mangle]
pub unsafe extern "system" fn PathIsFileSpecW(p: *const u16) -> Bool {
    let s = unsafe { wstr(p) };
    (!s.iter().any(|&c| is_sep(c) || c == b':' as u16)) as Bool
}

/// The last '.' of the file name part, or the terminating NUL.
#[no_mangle]
pub unsafe extern "system" fn PathFindExtensionW(p: *const u16) -> *const u16 {
    if p.is_null() {
        return p;
    }
    let s = unsafe { wstr(p) };
    let name = s.iter().rposition(|&c| is_sep(c)).map_or(0, |i| i + 1);
    match s[name..].iter().rposition(|&c| c == b'.' as u16) {
        Some(i) if !s[name + i..].iter().any(|&c| c == b' ' as u16) => unsafe { p.add(name + i) },
        _ => unsafe { p.add(s.len()) },
    }
}

#[no_mangle]
pub unsafe extern "system" fn PathFindFileNameW(p: *const u16) -> *const u16 {
    if p.is_null() {
        return p;
    }
    let s = unsafe { wstr(p) };
    let mut end = s.len();
    // A trailing separator belongs to the name before it.
    while end > 1 && is_sep(s[end - 1]) {
        end -= 1;
    }
    let start = s[..end].iter().rposition(|&c| is_sep(c) || c == b':' as u16).map_or(0, |i| i + 1);
    unsafe { p.add(start) }
}

#[no_mangle]
pub unsafe extern "system" fn PathRemoveFileSpecW(p: *mut u16) -> Bool {
    if p.is_null() {
        return 0;
    }
    let s = unsafe { wstr(p) };
    let Some(i) = s.iter().rposition(|&c| is_sep(c)) else {
        let had = !s.is_empty();
        unsafe { *p = 0 };
        return had as Bool;
    };
    // Keep the root's separator ("C:\").
    let cut = if i == 2 && s.get(1) == Some(&(b':' as u16)) || i == 0 { i + 1 } else { i };
    let changed = cut < s.len();
    unsafe { *p.add(cut) = 0 };
    changed as Bool
}

#[no_mangle]
pub unsafe extern "system" fn PathAddBackslashW(p: *mut u16) -> *mut u16 {
    let n = unsafe { crate::util::wlen(p) };
    if n > 0 && !is_sep(unsafe { *p.add(n - 1) }) {
        unsafe {
            *p.add(n) = BACKSLASH;
            *p.add(n + 1) = 0;
        }
        return unsafe { p.add(n + 1) };
    }
    unsafe { p.add(n) }
}

#[no_mangle]
pub unsafe extern "system" fn PathAppendW(p: *mut u16, more: *const u16) -> Bool {
    let more = unsafe { wstr(more) };
    let more = if more.first().is_some_and(|&c| is_sep(c)) { &more[1..] } else { more };
    unsafe { PathAddBackslashW(p) };
    let n = unsafe { crate::util::wlen(p) };
    unsafe {
        core::ptr::copy_nonoverlapping(more.as_ptr(), p.add(n), more.len());
        *p.add(n + more.len()) = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn PathIsRelativeW(p: *const u16) -> Bool {
    let s = unsafe { wstr(p) };
    let absolute = s.first().is_some_and(|&c| is_sep(c)) || (s.len() >= 2 && s[1] == b':' as u16);
    (!absolute) as Bool
}

/// UNC paths (two leading separators); VEILOS has no network drives.
#[no_mangle]
pub unsafe extern "system" fn PathIsNetworkPathW(p: *const u16) -> Bool {
    let s = unsafe { wstr(p) };
    (s.len() >= 2 && is_sep(s[0]) && is_sep(s[1])) as Bool
}

#[no_mangle]
pub unsafe extern "system" fn PathIsUNCW(p: *const u16) -> Bool {
    unsafe { PathIsNetworkPathW(p) }
}

#[no_mangle]
pub unsafe extern "system" fn PathRemoveExtensionW(p: *mut u16) {
    let e = unsafe { PathFindExtensionW(p) } as *mut u16;
    if !e.is_null() {
        unsafe { *e = 0 };
    }
}

#[no_mangle]
pub unsafe extern "system" fn PathRenameExtensionW(p: *mut u16, ext: *const u16) -> Bool {
    unsafe { PathRemoveExtensionW(p) };
    let n = unsafe { crate::util::wlen(p) };
    let e = unsafe { wstr(ext) };
    unsafe {
        core::ptr::copy_nonoverlapping(e.as_ptr(), p.add(n), e.len());
        *p.add(n + e.len()) = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn PathCombineW(out: *mut u16, dir: *const u16, file: *const u16) -> *mut u16 {
    if out.is_null() {
        return out;
    }
    let f = unsafe { wstr(file) };
    let d = unsafe { wstr(dir) };
    let start: &[u16] = if !f.is_empty() && unsafe { PathIsRelativeW(file) } == 0 { &[] } else { d };
    let n = start.len();
    unsafe {
        core::ptr::copy(start.as_ptr(), out, n);
        *out.add(n) = 0;
    }
    if !f.is_empty() {
        unsafe { PathAppendW(out, file) };
    }
    out
}

#[no_mangle]
pub unsafe extern "system" fn StrCmpIW(a: *const u16, b: *const u16) -> i32 {
    let (a, b) = unsafe { (wstr(a), wstr(b)) };
    let up = |c: u16| if (b'a' as u16..=b'z' as u16).contains(&c) { c - 32 } else { c };
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (up(*x) as i32, up(*y) as i32);
        if x != y {
            return x - y;
        }
    }
    a.len() as i32 - b.len() as i32
}

#[no_mangle]
pub unsafe extern "system" fn StrStrIW(s: *const u16, find: *const u16) -> *const u16 {
    let (h, n) = unsafe { (wstr(s), wstr(find)) };
    if n.is_empty() {
        return s;
    }
    let up = |c: u16| if (b'a' as u16..=b'z' as u16).contains(&c) { c - 32 } else { c };
    for i in 0..=h.len().saturating_sub(n.len()) {
        if h.len() >= n.len() && h[i..i + n.len()].iter().zip(n).all(|(a, b)| up(*a) == up(*b)) {
            return unsafe { s.add(i) };
        }
    }
    core::ptr::null()
}

/// A copy in CoTaskMemAlloc'd memory.
#[no_mangle]
pub unsafe extern "system" fn SHStrDupW(s: *const u16, out: *mut *mut u16) -> HResult {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let t = unsafe { wstr(s) };
    let p = CoTaskMemAlloc((t.len() + 1) * 2) as *mut u16;
    if p.is_null() {
        unsafe { *out = core::ptr::null_mut() };
        return E_OUTOFMEMORY;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(t.as_ptr(), p, t.len());
        *p.add(t.len()) = 0;
        *out = p;
    }
    S_OK
}

/// 96 dpi everywhere.
#[no_mangle]
pub unsafe extern "system" fn GetDpiForMonitor(_mon: usize, _kind: u32, x: *mut u32, y: *mut u32) -> HResult {
    unsafe {
        if !x.is_null() {
            *x = 96;
        }
        if !y.is_null() {
            *y = 96;
        }
    }
    S_OK
}

#[no_mangle]
pub extern "system" fn SetProcessDpiAwareness(_v: u32) -> HResult {
    S_OK
}

#[no_mangle]
pub unsafe extern "system" fn GetProcessDpiAwareness(_p: Handle, out: *mut u32) -> HResult {
    if !out.is_null() {
        unsafe { *out = 1 };
    }
    S_OK
}

#[no_mangle]
pub extern "system" fn GetScaleFactorForMonitor(_mon: usize, out: *mut u32) -> HResult {
    if !out.is_null() {
        unsafe { *out = 100 };
    }
    S_OK
}

// -----| urlmon, propsys: the parts programs reach for |-----

/// The MIME type from the name's extension, else from the data (text or
/// not). urlmon.dll forwards here.
#[no_mangle]
pub unsafe extern "system" fn FindMimeFromData(_bc: usize, url: *const u16, buf: *const u8, size: u32, proposed: *const u16,
                                               _flags: u32, out: *mut *mut u16, _reserved: u32) -> HResult {
    if out.is_null() || (url.is_null() && buf.is_null()) {
        return E_INVALIDARG;
    }
    // The extension, lower-case (up to 8 characters).
    let name = unsafe { wstr(url) };
    let mut ext = [0u8; 8];
    let mut n = 0;
    if let Some(i) = name.iter().rposition(|&c| c == b'.' as u16) {
        for &c in name[i + 1..].iter().take(8) {
            ext[n] = (c as u8).to_ascii_lowercase();
            n += 1;
        }
    }
    let by_ext = match &ext[..n] {
        b"txt" | b"log" | b"ini" | b"inf" | b"c" | b"h" | b"cpp" | b"rs" | b"md" | b"csv" | b"bat" | b"cmd" => Some("text/plain"),
        b"htm" | b"html" => Some("text/html"),
        b"xml" => Some("text/xml"),
        b"css" => Some("text/css"),
        b"png" => Some("image/png"),
        b"jpg" | b"jpeg" => Some("image/jpeg"),
        b"gif" => Some("image/gif"),
        b"bmp" => Some("image/bmp"),
        b"zip" => Some("application/x-zip-compressed"),
        b"pdf" => Some("application/pdf"),
        _ => None,
    };
    let mut buf16 = [0u16; 64];
    let mime: &[u16] = match by_ext {
        Some(m) => {
            let k = m.len();
            for (d, b) in buf16.iter_mut().zip(m.bytes()) {
                *d = b as u16;
            }
            &buf16[..k]
        }
        None if !proposed.is_null() => {
            let p = unsafe { wstr(proposed) };
            let k = p.len().min(63);
            buf16[..k].copy_from_slice(&p[..k]);
            &buf16[..k]
        }
        None => {
            let data = if buf.is_null() { &[][..] } else { unsafe { core::slice::from_raw_parts(buf, size as usize) } };
            let text = !data.is_empty() && data.iter().all(|&b| b >= 0x20 || matches!(b, 9 | 10 | 13));
            let m = if text { "text/plain" } else { "application/octet-stream" };
            for (d, b) in buf16.iter_mut().zip(m.bytes()) {
                *d = b as u16;
            }
            &buf16[..m.len()]
        }
    };
    let p = CoTaskMemAlloc((mime.len() + 1) * 2) as *mut u16;
    if p.is_null() {
        return E_OUTOFMEMORY;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(mime.as_ptr(), p, mime.len());
        *p.add(mime.len()) = 0;
        *out = p;
    }
    S_OK
}

/// No property system yet. propsys.dll forwards here.
#[no_mangle]
pub unsafe extern "system" fn PSGetPropertyDescriptionListFromString(_list: *const u16, _iid: *const u8, out: *mut usize) -> HResult {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    E_NOTIMPL
}

#[no_mangle]
pub unsafe extern "system" fn PropVariantToStringVectorAlloc(_pv: *const u8, out: *mut usize, count: *mut u32) -> HResult {
    unsafe {
        if !out.is_null() {
            *out = 0;
        }
        if !count.is_null() {
            *count = 0;
        }
    }
    E_NOTIMPL
}

/// IIDFromString accepts {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} or the
/// unbraced 36-character form, and stores GUID fields in little-endian order.
#[no_mangle]
pub unsafe extern "system" fn IIDFromString(text: *const u16, out: *mut [u8; 16]) -> HResult {
    const CO_E_IIDSTRING: HResult = 0x8004_01F3u32 as i32;
    if out.is_null() { return E_INVALIDARG; }
    if text.is_null() { unsafe { *out = [0; 16]; } return S_OK; }
    let wide = unsafe { wstr(text) };
    let body = if wide.len() == 38 && wide[0] == b'{' as u16 && wide[37] == b'}' as u16 {
        &wide[1..37]
    } else if wide.len() == 36 {
        wide
    } else {
        return CO_E_IIDSTRING;
    };
    if [8, 13, 18, 23].iter().any(|&i| body[i] != b'-' as u16) { return CO_E_IIDSTRING; }
    fn nibble(ch: u16) -> Option<u8> {
        match ch {
            48..=57 => Some((ch - 48) as u8),
            65..=70 => Some((ch - 55) as u8),
            97..=102 => Some((ch - 87) as u8),
            _ => None,
        }
    }
    let mut bytes = [0u8; 16];
    let mut n = 0;
    let mut at = 0;
    while at < 36 {
        if body[at] == b'-' as u16 { at += 1; continue; }
        let (Some(a), Some(b)) = (nibble(body[at]), nibble(body[at+1])) else { return CO_E_IIDSTRING; };
        bytes[n] = (a << 4) | b;
        n += 1;
        at += 2;
    }
    // GUID wire layout: Data1, Data2 and Data3 little-endian; Data4 as-is.
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    unsafe { *out = bytes; }
    S_OK
}

#[no_mangle]
pub unsafe extern "system" fn StringFromCLSID(guid: *const [u8; 16], out: *mut *mut u16) -> HResult {
    if guid.is_null() || out.is_null() { return E_INVALIDARG; }
    let dst = CoTaskMemAlloc(39 * 2) as *mut u16;
    if dst.is_null() { return E_OUTOFMEMORY; }
    if unsafe { StringFromGUID2(guid, dst, 39) } != 39 {
        CoTaskMemFree(dst as *mut u8);
        return E_FAIL;
    }
    unsafe { *out = dst; }
    S_OK
}

/// RPC UUID helpers can use the process's existing GUID generator. These
/// provide functional formatting/allocation, not cryptographic randomness.
#[no_mangle]
pub unsafe extern "system" fn UuidCreate(out: *mut [u8; 16]) -> u32 {
    if out.is_null() { return 87; } // RPC_S_INVALID_ARG
    if unsafe { CoCreateGuid(out) } == S_OK { 0 } else { 14 }
}

#[no_mangle]
pub unsafe extern "system" fn UuidToStringW(guid: *const [u8; 16], out: *mut *mut u16) -> u32 {
    if guid.is_null() || out.is_null() { return 87; }
    let dst = CoTaskMemAlloc(37 * 2) as *mut u16;
    if dst.is_null() { return 14; }
    let mut text = [0u16; 39];
    if unsafe { StringFromGUID2(guid, text.as_mut_ptr(), 39) } != 39 {
        CoTaskMemFree(dst as *mut u8);
        return 87;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr().add(1), dst, 36);
        *dst.add(36) = 0;
        *out = dst;
    }
    0
}

#[no_mangle]
pub unsafe extern "system" fn RpcStringFreeW(out: *mut *mut u16) -> u32 {
    if out.is_null() { return 87; }
    unsafe {
        CoTaskMemFree(*out as *mut u8);
        *out = core::ptr::null_mut();
    }
    0
}
