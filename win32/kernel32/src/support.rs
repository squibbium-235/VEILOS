//! What programs check on their way to doing real work: semaphores, the
//! process token (one standard user, not elevated), event tracing (ETW:
//! registered, never enabled), restart registration, processor features,
//! text helpers (IsTextUnicode, FindNLSString, FoldString, MulDiv), the
//! registry calls kernel32's empty registry was missing, file details by
//! handle, and the user name.

use crate::util::wstr;
use crate::{Bool, Handle};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_TOKEN: u32 = 1008;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_HANDLE: u32 = 6;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtCreateSemaphore(h: *mut Handle, access: u32, attrs: usize, initial: i32, max: i32) -> i32;
    fn NtReleaseSemaphore(h: Handle, count: i32, prev: *mut i32) -> i32;
}

// -----| semaphores |-----

#[no_mangle]
pub unsafe extern "system" fn CreateSemaphoreExW(_sa: usize, initial: i32, max: i32, name: *const u16, _flags: u32, access: u32) -> Handle {
    if let Some(found) = crate::named_existing(name, crate::KIND_SEMAPHORE) {
        return found;
    }
    let mut h: Handle = 0;
    let s = unsafe { NtCreateSemaphore(&mut h, access | 0x1F0003, 0, initial, max) };
    if s != 0 {
        crate::fail(s);
        return 0;
    }
    crate::name_new(h, name, crate::KIND_SEMAPHORE);
    h
}

#[no_mangle]
pub unsafe extern "system" fn CreateSemaphoreW(sa: usize, initial: i32, max: i32, name: *const u16) -> Handle {
    unsafe { CreateSemaphoreExW(sa, initial, max, name, 0, 0) }
}

#[no_mangle]
pub unsafe extern "system" fn CreateSemaphoreA(sa: usize, initial: i32, max: i32, name: *const u8) -> Handle {
    if name.is_null() {
        return unsafe { CreateSemaphoreExW(sa, initial, max, core::ptr::null(), 0, 0) };
    }
    let w = unsafe { crate::util::widen(name) };
    unsafe { CreateSemaphoreExW(sa, initial, max, w.as_ptr(), 0, 0) }
}

#[no_mangle]
pub unsafe extern "system" fn OpenSemaphoreW(_access: u32, _inherit: Bool, name: *const u16) -> Handle {
    crate::open_named(name, crate::KIND_SEMAPHORE)
}

#[no_mangle]
pub unsafe extern "system" fn OpenSemaphoreA(access: u32, inherit: Bool, name: *const u8) -> Handle {
    let w = unsafe { crate::util::widen(name) };
    unsafe { OpenSemaphoreW(access, inherit, w.as_ptr()) }
}

#[no_mangle]
pub unsafe extern "system" fn ReleaseSemaphore(h: Handle, count: i32, prev: *mut i32) -> Bool {
    crate::check(unsafe { NtReleaseSemaphore(h, count, prev) })
}

// -----| the token |-----

/// The process token: a pseudo handle the other token calls know.
const TOKEN: Handle = (-5i64) as u64;

#[no_mangle]
pub unsafe extern "system" fn OpenProcessToken(_process: Handle, _access: u32, out: *mut Handle) -> Bool {
    if out.is_null() {
        crate::SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    unsafe { *out = TOKEN };
    1
}

/// Threads don't impersonate.
#[no_mangle]
pub unsafe extern "system" fn OpenThreadToken(_thread: Handle, _access: u32, _self: Bool, out: *mut Handle) -> Bool {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    crate::SetLastError(ERROR_NO_TOKEN);
    0
}

/// The user's SID: S-1-5-21-1000-1000-1000-1001, as a local account.
const USER_SID: [u8; 28] = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xE8, 3, 0, 0, 0xE8, 3, 0, 0, 0xE8, 3, 0, 0, 0xE9, 3, 0, 0];
/// Medium integrity: S-1-16-8192.
const MEDIUM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0];

/// What ntdll says about the token (one user, the same everywhere).
#[no_mangle]
pub unsafe extern "system" fn GetTokenInformation(token: Handle, class: u32, out: *mut u8, size: u32, needed: *mut u32) -> Bool {
    #[link(name = "ntdll", kind = "raw-dylib")]
    unsafe extern "system" {
        fn NtQueryInformationToken(token: Handle, class: u32, info: *mut u8, len: u32, ret: *mut u32) -> i32;
    }
    let mut n = 0u32;
    let s = unsafe { NtQueryInformationToken(token, class, out, size, &mut n) };
    if !needed.is_null() {
        unsafe { *needed = n };
    }
    match s {
        0 => 1,
        st if st == 0xC000_0023u32 as i32 => {
            crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
            0
        }
        st if st == 0xC000_0003u32 as i32 => {
            crate::SetLastError(ERROR_INVALID_PARAMETER);
            0
        }
        st => crate::fail(st),
    }
}

#[no_mangle]
pub unsafe extern "system" fn GetUserNameW(out: *mut u16, size: *mut u32) -> Bool {
    let name: &[u16] = &[b'u' as u16, b's' as u16, b'e' as u16, b'r' as u16];
    if size.is_null() {
        return 0;
    }
    let cap = unsafe { *size } as usize;
    unsafe { *size = (name.len() + 1) as u32 };
    if out.is_null() || cap <= name.len() {
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), out, name.len());
        *out.add(name.len()) = 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn GetUserNameA(out: *mut u8, size: *mut u32) -> Bool {
    if size.is_null() {
        return 0;
    }
    let cap = unsafe { *size } as usize;
    unsafe { *size = 5 };
    if out.is_null() || cap < 5 {
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { core::ptr::copy_nonoverlapping(b"user\0".as_ptr(), out, 5) };
    1
}

// -----| event tracing: registered, never enabled |-----

#[no_mangle]
pub unsafe extern "system" fn EventRegister(_guid: *const u8, _cb: usize, _ctx: usize, out: *mut u64) -> u32 {
    if !out.is_null() {
        unsafe { *out = 1 };
    }
    0
}

#[no_mangle]
pub extern "system" fn EventUnregister(_h: u64) -> u32 {
    0
}

#[no_mangle]
pub extern "system" fn EventSetInformation(_h: u64, _class: u32, _info: usize, _len: u32) -> u32 {
    0
}

#[no_mangle]
pub extern "system" fn EventWrite(_h: u64, _desc: usize, _n: u32, _data: usize) -> u32 {
    0
}

#[no_mangle]
pub extern "system" fn EventWriteTransfer(_h: u64, _desc: usize, _act: usize, _rel: usize, _n: u32, _data: usize) -> u32 {
    0
}

#[no_mangle]
pub extern "system" fn EventWriteEx(_h: u64, _desc: usize, _filter: u64, _flags: u32, _act: usize, _rel: usize, _n: u32, _data: usize) -> u32 {
    0
}

#[no_mangle]
pub extern "system" fn EventEnabled(_h: u64, _desc: usize) -> Bool {
    0
}

#[no_mangle]
pub extern "system" fn EventProviderEnabled(_h: u64, _level: u8, _keyword: u64) -> Bool {
    0
}

#[no_mangle]
pub extern "system" fn EventActivityIdControl(_code: u32, _id: *mut u8) -> u32 {
    0
}

// -----| restart, processor, mitigations |-----

#[no_mangle]
pub extern "system" fn RegisterApplicationRestart(_cmdline: *const u16, _flags: u32) -> i32 {
    0
}

#[no_mangle]
pub extern "system" fn UnregisterApplicationRestart() -> i32 {
    0
}

#[no_mangle]
pub extern "system" fn RegisterApplicationRecoveryCallback(_cb: usize, _p: usize, _ping: u32, _flags: u32) -> i32 {
    0
}

/// PF_* features the x86-64 machine VEILOS runs on has.
#[no_mangle]
pub extern "system" fn IsProcessorFeaturePresent(feature: u32) -> Bool {
    // MMX, SSE, SSE2, SSE3, cmpxchg16b, NX, RDTSC, fast-fail, rdwrfsgsbase-free ones.
    matches!(feature, 3 | 6 | 7 | 8 | 10 | 12 | 13 | 17 | 23) as Bool
}

/// No mitigations: the policy structure all zero.
#[no_mangle]
pub unsafe extern "system" fn GetProcessMitigationPolicy(_p: Handle, _policy: u32, out: *mut u8, size: usize) -> Bool {
    if !out.is_null() {
        unsafe { core::ptr::write_bytes(out, 0, size) };
    }
    1
}

#[no_mangle]
pub extern "system" fn SetProcessMitigationPolicy(_policy: u32, _p: usize, _size: usize) -> Bool {
    1
}

// -----| text |-----

/// (a * b) / c rounded, or -1 if c is 0 or it overflows.
#[no_mangle]
pub extern "system" fn MulDiv(a: i32, b: i32, c: i32) -> i32 {
    if c == 0 {
        return -1;
    }
    // Rounded half away from zero.
    let (p, c) = (a as i64 * b as i64, c as i64);
    let q = (p.abs() + c.abs() / 2) / c.abs();
    let r = if (p < 0) != (c < 0) { -q } else { q };
    if r > i32::MAX as i64 || r < i32::MIN as i64 { -1 } else { r as i32 }
}

/// IS_TEXT_UNICODE_*: what the bytes look like, as Windows guesses it
/// (a byte-order mark, or a zero high byte in most characters).
#[no_mangle]
pub unsafe extern "system" fn IsTextUnicode(buf: *const u8, len: i32, flags: *mut i32) -> Bool {
    if buf.is_null() || len < 2 {
        if !flags.is_null() {
            unsafe { *flags = 0 };
        }
        return 0;
    }
    let b = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    let mut found = 0i32;
    if b[0] == 0xFF && b[1] == 0xFE {
        found |= 0x8; // IS_TEXT_UNICODE_SIGNATURE
    }
    if b[0] == 0xFE && b[1] == 0xFF {
        found |= 0x80; // IS_TEXT_UNICODE_REVERSE_SIGNATURE
    }
    let pairs = b.len() / 2;
    let high_zero = (0..pairs).filter(|i| b[i * 2 + 1] == 0 && b[i * 2] != 0).count();
    let low_zero = (0..pairs).filter(|i| b[i * 2] == 0 && b[i * 2 + 1] != 0).count();
    if pairs > 0 && high_zero * 3 >= pairs * 2 {
        found |= 0x2; // IS_TEXT_UNICODE_STATISTICS
    }
    if pairs > 0 && low_zero * 3 >= pairs * 2 {
        found |= 0x20; // IS_TEXT_UNICODE_REVERSE_STATISTICS
    }
    if b.len() % 2 == 1 {
        found |= 0x200; // IS_TEXT_UNICODE_ODD_LENGTH
    }
    if b.iter().any(|&c| c == 0) && b.chunks(2).any(|c| c.len() == 2 && c[0] == 0 && c[1] == 0) {
        found |= 0x1000; // IS_TEXT_UNICODE_NULL_BYTES
    }
    let wanted = if flags.is_null() { 0xF00F } else { unsafe { *flags } };
    let wanted = if wanted == 0 { 0xF00F } else { wanted };
    if !flags.is_null() {
        unsafe { *flags = found & wanted };
    }
    let unicode = found & (0x8 | 0x2) != 0 && found & (0x80 | 0x20 | 0x200) == 0;
    unicode as Bool
}

/// Find `find` in `src` (case-insensitively with NORM_IGNORECASE /
/// LINGUISTIC_IGNORECASE): its index, or -1.
#[no_mangle]
pub unsafe extern "system" fn FindNLSStringEx(_locale: *const u16, flags: u32, src: *const u16, n: i32, find: *const u16, fnum: i32,
                                              found: *mut i32, _ver: usize, _res: usize, _param: isize) -> i32 {
    let s = if n < 0 { unsafe { wstr(src) } } else { unsafe { core::slice::from_raw_parts(src, n as usize) } };
    let f = if fnum < 0 { unsafe { wstr(find) } } else { unsafe { core::slice::from_raw_parts(find, fnum as usize) } };
    let fold = flags & (0x1 | 0x10) != 0;
    let up = |c: u16| if fold && (b'a' as u16..=b'z' as u16).contains(&c) { c - 32 } else { c };
    let at = |i: usize| i + f.len() <= s.len() && s[i..i + f.len()].iter().zip(f).all(|(a, b)| up(*a) == up(*b));
    let hit = match flags & 0x00F0_0000 {
        0x0010_0000 => at(0).then_some(0),                                               // FIND_STARTSWITH
        0x0020_0000 => s.len().checked_sub(f.len()).filter(|&i| at(i)),                  // FIND_ENDSWITH
        0x0080_0000 => (0..=s.len().saturating_sub(f.len())).rev().find(|&i| at(i)),     // FIND_FROMEND
        _ => (0..=s.len().saturating_sub(f.len())).find(|&i| at(i)),                     // FIND_FROMSTART
    };
    match hit {
        Some(i) if f.len() <= s.len() => {
            if !found.is_null() {
                unsafe { *found = f.len() as i32 };
            }
            i as i32
        }
        _ => -1,
    }
}

#[no_mangle]
pub unsafe extern "system" fn FindNLSString(_lcid: u32, flags: u32, src: *const u16, n: i32, find: *const u16, fnum: i32, found: *mut i32) -> i32 {
    unsafe { FindNLSStringEx(core::ptr::null(), flags, src, n, find, fnum, found, 0, 0, 0) }
}

/// No folding beyond a copy (the text is already in its plain forms).
#[no_mangle]
pub unsafe extern "system" fn FoldStringW(_flags: u32, src: *const u16, n: i32, out: *mut u16, cap: i32) -> i32 {
    let s = if n < 0 { unsafe { core::slice::from_raw_parts(src, crate::util::wlen(src) + 1) } } else { unsafe { core::slice::from_raw_parts(src, n as usize) } };
    if cap == 0 {
        return s.len() as i32;
    }
    if (cap as usize) < s.len() {
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), out, s.len()) };
    s.len() as i32
}

// -----| files and modules |-----

/// BY_HANDLE_FILE_INFORMATION: attributes, three times, serial, sizes,
/// links, index.
#[no_mangle]
pub unsafe extern "system" fn GetFileInformationByHandle(h: Handle, out: *mut u8) -> Bool {
    if out.is_null() {
        return 0;
    }
    // FILE_BASIC_INFO: four times then attributes; FILE_STANDARD_INFO:
    // allocation, size, links.
    let mut basic = [0u8; 40];
    let mut std = [0u8; 24];
    if unsafe { crate::system::GetFileInformationByHandleEx(h, 0, basic.as_mut_ptr(), 40) } == 0
        || unsafe { crate::system::GetFileInformationByHandleEx(h, 1, std.as_mut_ptr(), 24) } == 0
    {
        return 0;
    }
    let mut info = [0u8; 52];
    info[0..4].copy_from_slice(&basic[32..36]);
    info[4..12].copy_from_slice(&basic[0..8]);
    info[12..20].copy_from_slice(&basic[8..16]);
    info[20..28].copy_from_slice(&basic[16..24]);
    info[28..32].copy_from_slice(&0x5645_494Cu32.to_le_bytes());
    let size = u64::from_le_bytes(std[8..16].try_into().unwrap());
    info[32..36].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
    info[36..40].copy_from_slice(&(size as u32).to_le_bytes());
    info[40..44].copy_from_slice(&u32::from_le_bytes(std[16..20].try_into().unwrap()).max(1).to_le_bytes());
    // nFileIndexHigh, then nFileIndexLow.
    let mut index = 0u64;
    let mut iosb = nt_abi::IoStatusBlock::default();
    unsafe { crate::NtQueryInformationFile(h, &mut iosb, &mut index as *mut u64 as *mut u8, 8, nt_abi::file::INTERNAL_INFORMATION) };
    info[44..48].copy_from_slice(&((index >> 32) as u32).to_le_bytes());
    info[48..52].copy_from_slice(&(index as u32).to_le_bytes());
    unsafe { core::ptr::copy_nonoverlapping(info.as_ptr(), out, 52) };
    1
}

/// Another process's modules aren't visible: this process's only.
#[no_mangle]
pub unsafe extern "system" fn K32GetModuleFileNameExW(process: Handle, module: Handle, out: *mut u16, size: u32) -> u32 {
    if process != u64::MAX && process != 0 {
        crate::SetLastError(ERROR_ACCESS_DENIED);
        return 0;
    }
    unsafe { crate::module::GetModuleFileNameW(module, out, size) }
}

#[no_mangle]
pub unsafe extern "system" fn GetModuleFileNameExW(process: Handle, module: Handle, out: *mut u16, size: u32) -> u32 {
    unsafe { K32GetModuleFileNameExW(process, module, out, size) }
}

/// No encrypting file system.
#[no_mangle]
pub extern "system" fn DecryptFileW(_name: *const u16, _r: u32) -> Bool {
    crate::SetLastError(50); // ERROR_NOT_SUPPORTED
    0
}

#[no_mangle]
pub extern "system" fn DuplicateEncryptionInfoFile(_src: *const u16, _dst: *const u16, _disp: u32, _attrs: u32, _sa: usize) -> u32 {
    50
}

// -----| printers: none (winspool.drv forwards here) |-----

const ERROR_INVALID_PRINTER_NAME: u32 = 1801;

#[no_mangle]
pub unsafe extern "system" fn OpenPrinterW(_name: *const u16, out: *mut Handle, _defaults: *const u8) -> Bool {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    crate::SetLastError(ERROR_INVALID_PRINTER_NAME);
    0
}

#[no_mangle]
pub unsafe extern "system" fn OpenPrinterA(name: *const u8, out: *mut Handle, defaults: *const u8) -> Bool {
    let _ = name;
    unsafe { OpenPrinterW(core::ptr::null(), out, defaults) }
}

#[no_mangle]
pub extern "system" fn ClosePrinter(_h: Handle) -> Bool {
    crate::SetLastError(ERROR_INVALID_HANDLE);
    0
}

#[no_mangle]
pub extern "system" fn GetPrinterDriverW(_h: Handle, _env: *const u16, _level: u32, _buf: *mut u8, _size: u32, needed: *mut u32) -> Bool {
    if !needed.is_null() {
        unsafe { *needed = 0 };
    }
    crate::SetLastError(ERROR_INVALID_HANDLE);
    0
}

/// No printers: success, with none listed.
#[no_mangle]
pub unsafe extern "system" fn EnumPrintersW(_flags: u32, _name: *const u16, _level: u32, _buf: *mut u8, _size: u32,
                                            needed: *mut u32, returned: *mut u32) -> Bool {
    unsafe {
        if !needed.is_null() {
            *needed = 0;
        }
        if !returned.is_null() {
            *returned = 0;
        }
    }
    1
}

/// ERROR_FILE_NOT_FOUND: there's no default printer.
#[no_mangle]
pub unsafe extern "system" fn GetDefaultPrinterW(_buf: *mut u16, size: *mut u32) -> Bool {
    if !size.is_null() {
        unsafe { *size = 0 };
    }
    crate::SetLastError(2);
    0
}

#[no_mangle]
pub extern "system" fn DocumentPropertiesW(_hwnd: u64, _h: Handle, _name: *const u16, _out: *mut u8, _in: *const u8, _mode: u32) -> i32 {
    -1
}

// -----| SIDs |-----

/// A SID's parts: revision, sub-authority count, six authority bytes, then the
/// sub-authorities.
unsafe fn sid_len(sid: *const u8) -> usize {
    8 + 4 * unsafe { *sid.add(1) } as usize
}

#[no_mangle]
pub unsafe extern "system" fn IsValidSid(sid: *const u8) -> Bool {
    (!sid.is_null() && unsafe { *sid == 1 && *sid.add(1) <= 15 }) as Bool
}

#[no_mangle]
pub unsafe extern "system" fn GetLengthSid(sid: *const u8) -> u32 {
    unsafe { sid_len(sid) as u32 }
}

#[no_mangle]
pub unsafe extern "system" fn EqualSid(a: *const u8, b: *const u8) -> Bool {
    crate::SetLastError(0);
    let n = unsafe { sid_len(a) };
    (n == unsafe { sid_len(b) } && unsafe { core::slice::from_raw_parts(a, n) == core::slice::from_raw_parts(b, n) }) as Bool
}

#[no_mangle]
pub unsafe extern "system" fn CopySid(size: u32, out: *mut u8, sid: *const u8) -> Bool {
    let n = unsafe { sid_len(sid) };
    if (size as usize) < n {
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { core::ptr::copy_nonoverlapping(sid, out, n) };
    1
}

#[no_mangle]
pub unsafe extern "system" fn AllocateAndInitializeSid(authority: *const u8, count: u8, a0: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32, a6: u32, a7: u32, out: *mut *mut u8) -> Bool {
    if authority.is_null() || out.is_null() || count == 0 || count > 8 {
        crate::SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let sid = crate::mem::LocalAlloc(0, 8 + 4 * count as usize);
    if sid.is_null() {
        return 0;
    }
    let parts = [a0, a1, a2, a3, a4, a5, a6, a7];
    unsafe {
        *sid = 1;
        *sid.add(1) = count;
        core::ptr::copy_nonoverlapping(authority, sid.add(2), 6);
        for i in 0..count as usize {
            (sid.add(8 + 4 * i) as *mut u32).write_unaligned(parts[i]);
        }
        *out = sid;
    }
    1
}

#[no_mangle]
pub extern "system" fn FreeSid(sid: *mut u8) -> *mut u8 {
    crate::mem::LocalFree(sid);
    core::ptr::null_mut()
}

/// The well-known SIDs programs ask about, by WELL_KNOWN_SID_TYPE.
#[no_mangle]
pub unsafe extern "system" fn IsWellKnownSid(sid: *const u8, kind: u32) -> Bool {
    let want: &[u8] = match kind {
        1 => &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],                  // Everyone
        17 => &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0],                // Authenticated Users
        22 => &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],                // Local System
        26 => &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0], // Administrators
        _ => return 0,
    };
    let n = unsafe { sid_len(sid) };
    (n == want.len() && unsafe { core::slice::from_raw_parts(sid, n) } == want) as Bool
}

/// The one user is in no group a program would ask about, but is itself.
#[no_mangle]
pub unsafe extern "system" fn CheckTokenMembership(_token: Handle, sid: *const u8, member: *mut Bool) -> Bool {
    if sid.is_null() || member.is_null() {
        crate::SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    unsafe { *member = EqualSid(sid, USER_SID.as_ptr()) };
    1
}

/// "S-1-5-18", returning its length.
unsafe fn sid_text(sid: *const u8, out: &mut [u8; 192]) -> usize {
    fn number(out: &mut [u8; 192], at: &mut usize, mut v: u64) {
        let mut digits = [0u8; 20];
        let mut n = 0;
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        out[*at] = b'-';
        *at += 1;
        while n > 0 {
            n -= 1;
            out[*at] = digits[n];
            *at += 1;
        }
    }
    out[0] = b'S';
    let mut at = 1;
    number(out, &mut at, unsafe { *sid } as u64);
    let mut authority = 0u64;
    for i in 0..6 {
        authority = authority << 8 | unsafe { *sid.add(2 + i) } as u64;
    }
    number(out, &mut at, authority);
    for i in 0..unsafe { *sid.add(1) } as usize {
        number(out, &mut at, unsafe { (sid.add(8 + 4 * i) as *const u32).read_unaligned() } as u64);
    }
    at
}

#[no_mangle]
pub unsafe extern "system" fn ConvertSidToStringSidA(sid: *const u8, out: *mut *mut u8) -> Bool {
    if unsafe { IsValidSid(sid) } == 0 || out.is_null() {
        crate::SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let mut text = [0u8; 192];
    let n = unsafe { sid_text(sid, &mut text) };
    let p = crate::mem::LocalAlloc(0, n + 1);
    if p.is_null() {
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), p, n);
        *p.add(n) = 0;
        *out = p;
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn ConvertSidToStringSidW(sid: *const u8, out: *mut *mut u16) -> Bool {
    if unsafe { IsValidSid(sid) } == 0 || out.is_null() {
        crate::SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    let mut text = [0u8; 192];
    let n = unsafe { sid_text(sid, &mut text) };
    let p = crate::mem::LocalAlloc(0, 2 * (n + 1)) as *mut u16;
    if p.is_null() {
        return 0;
    }
    unsafe {
        for i in 0..n {
            p.add(i).write_unaligned(text[i] as u16);
        }
        p.add(n).write_unaligned(0);
        *out = p;
    }
    1
}

/// FAT keeps no owners, so everything belongs to the user: the owner and group
/// of any file that exists are the user's SID, and there is no DACL. The caller
/// frees `descriptor` with LocalFree; the SID pointers point into it.
#[no_mangle]
pub unsafe extern "system" fn GetNamedSecurityInfoW(name: *const u16, kind: u32, _info: u32, owner: *mut *const u8, group: *mut *const u8, dacl: *mut usize, sacl: *mut usize, descriptor: *mut *mut u8) -> u32 {
    const SE_FILE_OBJECT: u32 = 1;
    if kind != SE_FILE_OBJECT || name.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if unsafe { crate::file::GetFileAttributesW(name) } == u32::MAX {
        return crate::GetLastError();
    }
    // A self-relative SECURITY_DESCRIPTOR: revision, control, then offsets to
    // owner, group, SACL and DACL.
    let size = 20 + USER_SID.len();
    let sd = crate::mem::LocalAlloc(0x40, size);
    if sd.is_null() {
        return crate::GetLastError();
    }
    unsafe {
        *sd = 1;
        (sd.add(2) as *mut u16).write_unaligned(0x8000);
        (sd.add(4) as *mut u32).write_unaligned(20);
        (sd.add(8) as *mut u32).write_unaligned(20);
        core::ptr::copy_nonoverlapping(USER_SID.as_ptr(), sd.add(20), USER_SID.len());
        if !owner.is_null() {
            *owner = sd.add(20);
        }
        if !group.is_null() {
            *group = sd.add(20);
        }
        if !dacl.is_null() {
            *dacl = 0;
        }
        if !sacl.is_null() {
            *sacl = 0;
        }
        if descriptor.is_null() {
            crate::mem::LocalFree(sd);
        } else {
            *descriptor = sd;
        }
    }
    0
}

// -----| byte order |-----

// ws2_32's, but programs use them with no socket in sight: git writes its index
// with htons, and a stub answering 0 saved every file name's length as 0.
#[no_mangle]
pub extern "system" fn htons(v: u16) -> u16 {
    v.to_be()
}

#[no_mangle]
pub extern "system" fn ntohs(v: u16) -> u16 {
    u16::from_be(v)
}

#[no_mangle]
pub extern "system" fn htonl(v: u32) -> u32 {
    v.to_be()
}

#[no_mangle]
pub extern "system" fn ntohl(v: u32) -> u32 {
    u32::from_be(v)
}

const ERROR_EVENTLOG_NOT_IMPLEMENTED: u32 = 120;

#[no_mangle]
pub extern "system" fn RegisterEventSourceW(
    _server: *const u16,
    _source: *const u16,
) -> Handle {
    crate::SetLastError(ERROR_EVENTLOG_NOT_IMPLEMENTED);
    0
}

#[no_mangle]
pub extern "system" fn RegisterEventSourceA(
    _server: *const u8,
    _source: *const u8,
) -> Handle {
    crate::SetLastError(ERROR_EVENTLOG_NOT_IMPLEMENTED);
    0
}

#[no_mangle]
pub extern "system" fn DeregisterEventSource(
    _handle: Handle,
) -> Bool {
    crate::SetLastError(ERROR_EVENTLOG_NOT_IMPLEMENTED);
    0
}

#[no_mangle]
pub extern "system" fn ReportEventW(
    _handle: Handle,
    _kind: u16,
    _category: u16,
    _event_id: u32,
    _sid: *const u8,
    _strings_count: u16,
    _data_size: u32,
    _strings: *const *const u16,
    _data: *const u8,
) -> Bool {
    crate::SetLastError(ERROR_EVENTLOG_NOT_IMPLEMENTED);
    0
}

#[no_mangle]
pub extern "system" fn ReportEventA(
    _handle: Handle,
    _kind: u16,
    _category: u16,
    _event_id: u32,
    _sid: *const u8,
    _strings_count: u16,
    _data_size: u32,
    _strings: *const *const u8,
    _data: *const u8,
) -> Bool {
    crate::SetLastError(ERROR_EVENTLOG_NOT_IMPLEMENTED);
    0
}

const E_NOTIMPL: i32 = 0x80004001u32 as i32;

#[no_mangle]
pub extern "system" fn WerRegisterRuntimeExceptionModule(
    _dll: *const u16,
    _context: *mut core::ffi::c_void,
) -> i32 {
    // VEILOS does not yet provide Windows Error Reporting.
    E_NOTIMPL
}

#[no_mangle]
pub extern "system" fn WerUnregisterRuntimeExceptionModule(
    _dll: *const u16,
    _context: *mut core::ffi::c_void,
) -> i32 {
    E_NOTIMPL
}
