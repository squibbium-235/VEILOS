//! Win32 compatibility APIs backed by existing VEILOS process, timer, heap,
//! and virtual-memory facilities. Unsupported features report errors rather
//! than claiming success.
use crate::{Bool, Handle};
use nt_abi::{status, CURRENT_PROCESS};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NOT_SUPPORTED: u32 = 50;
const APPMODEL_ERROR_NO_PACKAGE: u32 = 15700;

/// A caller's real thread entry. On VEILOS the kernel starts threads through
/// ntdll's RtlUserThreadStart; this export also supports dynamic lookups.
#[no_mangle]
pub unsafe extern "system" fn BaseThreadInitThunk(
    _flags: u32,
    start: unsafe extern "system" fn(usize) -> u32,
    arg: usize,
) -> ! {
    let exit_code = unsafe { start(arg) };
    crate::process::ExitThread(exit_code)
}

#[no_mangle]
pub extern "system" fn GetProcessHeaps(count: u32, heaps: *mut Handle) -> u32 {
    if count == 0 { return 1; }
    if heaps.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    unsafe { *heaps = crate::mem::GetProcessHeap(); }
    1
}

/// The kernel does not yet expose a process handle-table count.
#[no_mangle]
pub unsafe extern "system" fn GetProcessHandleCount(_process: Handle, count: *mut u32) -> Bool {
    if count.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    crate::SetLastError(ERROR_NOT_SUPPORTED);
    0
}

#[no_mangle]
pub unsafe extern "system" fn VirtualAllocEx(process: Handle, address: usize, size: usize, kind: u32, protection: u32) -> usize {
    let (mut base, mut length) = (address, size);
    let s = unsafe { crate::NtAllocateVirtualMemory(process, &mut base, 0, &mut length, kind, protection) };
    if status::is_success(s) { base } else { crate::fail(s); 0 }
}

#[no_mangle]
pub unsafe extern "system" fn VirtualFreeEx(process: Handle, address: usize, size: usize, kind: u32) -> Bool {
    if kind & 0x8000 != 0 && size != 0 { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    let (mut base, mut length) = (address, size);
    crate::check(unsafe { crate::NtFreeVirtualMemory(process, &mut base, &mut length, kind) })
}

/// Local timer implementation already exists; convert its ANSI name and
/// hand off to CreateWaitableTimerExW.
#[no_mangle]
pub unsafe extern "system" fn CreateWaitableTimerExA(sa: usize, name: *const u8, flags: u32, access: u32) -> Handle {
    if name.is_null() { return crate::wait::CreateWaitableTimerExW(sa, core::ptr::null(), flags, access); }
    let w = unsafe { crate::util::widen(name) };
    crate::wait::CreateWaitableTimerExW(sa, w.as_ptr(), flags, access)
}

#[no_mangle]
pub unsafe extern "system" fn QueryFullProcessImageNameA(process: Handle, flags: u32, out: *mut u8, size: *mut u32) -> Bool {
    if out.is_null() || size.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    let mut tmp = [0u16; 1024];
    let mut chars = tmp.len() as u32;
    if unsafe { crate::process::QueryFullProcessImageNameW(process, flags, tmp.as_mut_ptr(), &mut chars) } == 0 { return 0; }
    if unsafe { *size } <= chars { crate::SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
    unsafe {
        for i in 0..chars as usize { *out.add(i) = if tmp[i] < 256 { tmp[i] as u8 } else { b'?' }; }
        *out.add(chars as usize) = 0;
        *size = chars;
    }
    1
}

/// VEILOS processes are unpackaged desktop applications. These return the
/// documented error code instead of claiming an invented package identity.
/// Win32 PACKAGE_ID query: ordinary VEILOS processes are unpackaged.
/// Unlike a success stub, APPMODEL_ERROR_NO_PACKAGE lets callers use their
/// existing unpackaged-desktop fallback path.
#[no_mangle]
pub unsafe extern "system" fn GetCurrentPackageId(length: *mut u32, _buffer: *mut u8) -> u32 {
    if length.is_null() { return ERROR_INVALID_PARAMETER; }
    APPMODEL_ERROR_NO_PACKAGE
}

#[no_mangle]
pub unsafe extern "system" fn GetCurrentPackageFullName(length: *mut u32, _name: *mut u16) -> u32 {
    if length.is_null() { return ERROR_INVALID_PARAMETER; }
    APPMODEL_ERROR_NO_PACKAGE
}

#[no_mangle]
pub unsafe extern "system" fn GetCurrentPackageFamilyName(length: *mut u32, _name: *mut u16) -> u32 {
    if length.is_null() { return ERROR_INVALID_PARAMETER; }
    APPMODEL_ERROR_NO_PACKAGE
}

#[no_mangle]
pub unsafe extern "system" fn GetCurrentApplicationUserModelId(length: *mut u32, _name: *mut u16) -> u32 {
    if length.is_null() { return ERROR_INVALID_PARAMETER; }
    APPMODEL_ERROR_NO_PACKAGE
}

/// No Windows product SKU exists for VEILOS; the documented PRODUCT_UNDEFINED
/// value (0) describes the result without spoofing an edition of Windows.
#[no_mangle]
pub unsafe extern "system" fn GetProductInfo(
    _major: u32, _minor: u32, _service_major: u32, _service_minor: u32,
    product: *mut u32,
) -> Bool {
    if product.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    unsafe { *product = 0; }
    1
}

#[no_mangle]
pub extern "system" fn SetDefaultDllDirectories(_flags: u32) -> Bool {
    crate::SetLastError(120); // custom loader search paths not implemented
    0
}

#[no_mangle]
pub extern "system" fn SetThreadInformation(_thread: Handle, _class: u32, _info: *const u8, _len: u32) -> Bool {
    crate::SetLastError(ERROR_NOT_SUPPORTED);
    0
}

#[no_mangle]
pub extern "system" fn TerminateJobObject(_job: Handle, _code: u32) -> Bool {
    crate::SetLastError(ERROR_NOT_SUPPORTED);
    0
}

/// Deprecated IsBadReadPtr. Check every covered MEMORY_BASIC_INFORMATION
/// region; this is diagnostic only and is subject to the usual TOCTOU race.
#[no_mangle]
pub unsafe extern "system" fn IsBadReadPtr(pointer: *const u8, length: usize) -> Bool {
    if length == 0 { return 0; }
    if pointer.is_null() { return 1; }
    let start = pointer as usize;
    let Some(end) = start.checked_add(length) else { return 1; };
    let mut cursor = start;
    while cursor < end {
        let mut info = [0u8; 48];
        if unsafe { crate::mem::VirtualQuery(cursor, info.as_mut_ptr(), info.len()) } < 48 { return 1; }
        let base = usize::from_le_bytes(info[0..8].try_into().unwrap());
        let region = usize::from_le_bytes(info[24..32].try_into().unwrap());
        let state = u32::from_le_bytes(info[32..36].try_into().unwrap());
        let protect = u32::from_le_bytes(info[36..40].try_into().unwrap());
        let Some(next) = base.checked_add(region) else { return 1; };
        if next <= cursor || state != 0x1000 || protect & (0x1 | 0x100) != 0 { return 1; }
        cursor = next.min(end);
    }
    0
}

#[no_mangle]
pub unsafe extern "system" fn GetComputerNameA(out: *mut u8, cap: *mut u32) -> Bool {
    if cap.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    let mut w = [0u16; 256];
    let mut wc = w.len() as u32;
    if unsafe { crate::legacy::GetComputerNameW(w.as_mut_ptr(), &mut wc) } == 0 { return 0; }
    if unsafe { *cap } <= wc || out.is_null() {
        unsafe { *cap = wc + 1; }
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        for i in 0..wc as usize { *out.add(i) = if w[i] <= 255 { w[i] as u8 } else { b'?' }; }
        *out.add(wc as usize) = 0;
        *cap = wc;
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn GetComputerNameExA(format: u32, out: *mut u8, cap: *mut u32) -> Bool {
    if cap.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    let mut w = [0u16; 256];
    let mut wc = w.len() as u32;
    if unsafe { crate::bun::GetComputerNameExW(format, w.as_mut_ptr(), &mut wc) } == 0 { return 0; }
    if unsafe { *cap } <= wc || out.is_null() {
        unsafe { *cap = wc + 1; }
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        for i in 0..wc as usize { *out.add(i) = if w[i] <= 255 { w[i] as u8 } else { b'?' }; }
        *out.add(wc as usize) = 0;
        *cap = wc;
    }
    1
}

#[no_mangle]
pub extern "system" fn GetMaximumProcessorGroupCount() -> u16 { 1 }
#[no_mangle]
pub extern "system" fn GetMaximumProcessorCount(group: u16) -> u32 {
    if group != 0 { return 0; }
    let mut info = [0u8; 48];
    unsafe { crate::mem::GetSystemInfo(info.as_mut_ptr()) };
    u32::from_le_bytes(info[32..36].try_into().unwrap())
}

#[no_mangle]
pub unsafe extern "system" fn lstrcpyW(out: *mut u16, input: *const u16) -> *mut u16 {
    if out.is_null() || input.is_null() { return core::ptr::null_mut(); }
    let n = unsafe { crate::util::wlen(input) } + 1;
    unsafe { core::ptr::copy(input, out, n); }
    out
}

#[no_mangle]
pub unsafe extern "system" fn lstrcpyA(out: *mut u8, input: *const u8) -> *mut u8 {
    if out.is_null() || input.is_null() { return core::ptr::null_mut(); }
    let n = unsafe { crate::util::alen(input) } + 1;
    unsafe { core::ptr::copy(input, out, n); }
    out
}

#[no_mangle]
pub unsafe extern "system" fn lstrcatW(out: *mut u16, input: *const u16) -> *mut u16 {
    if out.is_null() || input.is_null() { return core::ptr::null_mut(); }
    let len = unsafe { crate::util::wlen(out) };
    unsafe { lstrcpyW(out.add(len), input) };
    out
}

#[no_mangle]
pub unsafe extern "system" fn lstrcpynW(out: *mut u16, input: *const u16, max: i32) -> *mut u16 {
    if out.is_null() || input.is_null() || max <= 0 { return core::ptr::null_mut(); }
    let n = unsafe { crate::util::wlen(input) }.min(max as usize - 1);
    unsafe { core::ptr::copy(input, out, n); *out.add(n) = 0; }
    out
}

#[no_mangle]
pub unsafe extern "system" fn lstrcpynA(out: *mut u8, input: *const u8, max: i32) -> *mut u8 {
    if out.is_null() || input.is_null() || max <= 0 { return core::ptr::null_mut(); }
    let n = unsafe { crate::util::alen(input) }.min(max as usize - 1);
    unsafe { core::ptr::copy(input, out, n); *out.add(n) = 0; }
    out
}

/// VEILOS's single interactive session has session ID zero.
#[no_mangle]
pub extern "system" fn WTSGetActiveConsoleSessionId() -> u32 { 0 }

/// SYSTEM_POWER_STATUS: report unknown values instead of manufacturing a
/// battery, charger, or AC source that the OS cannot query.
#[no_mangle]
pub unsafe extern "system" fn GetSystemPowerStatus(out: *mut u8) -> Bool {
    if out.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    unsafe {
        *out.add(0) = 255; // ACLineStatus unknown
        *out.add(1) = 255; // BatteryFlag unknown
        *out.add(2) = 255; // BatteryLifePercent unknown
        *out.add(3) = 0;   // reserved
        (out.add(4) as *mut u32).write_unaligned(u32::MAX);
        (out.add(8) as *mut u32).write_unaligned(u32::MAX);
    }
    1
}

/// GetUserPreferredUILanguages: one user-configured English locale for now.
/// Output is a MULTI_SZ (two terminating NULs).
#[no_mangle]
pub unsafe extern "system" fn GetUserPreferredUILanguages(
    flags: u32, number: *mut u32, buffer: *mut u16, capacity: *mut u32,
) -> Bool {
    if number.is_null() || capacity.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    // MUI_LANGUAGE_NAME=8, MUI_LANGUAGE_ID=4; mutually exclusive.
    if (flags & 0x0c) == 0x0c { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    let name: &[u16] = if flags & 0x08 != 0 {
        &[b'e' as u16, b'n' as u16, b'-' as u16, b'U' as u16, b'S' as u16, 0, 0]
    } else {
        &[b'0' as u16, b'4' as u16, b'0' as u16, b'9' as u16, 0, 0]
    };
    let available = unsafe { *capacity } as usize;
    unsafe { *number = 1; *capacity = name.len() as u32; }
    if available < name.len() || buffer.is_null() {
        // Size discovery with a NULL buffer is a supported pattern.
        if buffer.is_null() && available == 0 { return 1; }
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), buffer, name.len()); }
    1
}
