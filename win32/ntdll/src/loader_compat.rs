//! NTDLL loader entry points over VEILOS's real per-process image loader.
use nt_abi::{status, InitCall, NtStatus};
use crate::rtl::UnicodeString;

#[no_mangle]
pub unsafe extern "system" fn LdrLoadDll(
    _search_path: *const u16,
    _flags: *const u32,
    dll_name: *const UnicodeString,
    module_out: *mut u64,
) -> NtStatus {
    if dll_name.is_null() || module_out.is_null() {
        return status::INVALID_PARAMETER;
    }
    let dll = unsafe { &*dll_name };
    if dll.buffer.is_null() || dll.length == 0 || dll.length % 2 != 0 {
        return status::INVALID_PARAMETER;
    }
    let mut base = 0u64;
    let mut inits = [InitCall::default(); 128];
    let mut count = 0u32;
    crate::thread::LdrVeilTlsBegin();
    // Nt syscall IDs have no compiler-known signatures, so declare the proper
    // x64 six-argument signature at the Rust call site.
    let load: unsafe extern "system" fn(*const u16, usize, *mut u64, *mut InitCall, usize, *mut u32) -> NtStatus =
        unsafe { core::mem::transmute(crate::VeilLoadDll as usize) };
    let result = unsafe { load(dll.buffer, dll.length as usize / 2, &mut base, inits.as_mut_ptr(), inits.len(), &mut count) };
    crate::thread::LdrVeilTlsEnd();
    if !status::is_success(result) { return result; }
    if count as usize > inits.len() { return status::INVALID_PARAMETER; }
    type Entry = unsafe extern "system" fn(u64, u32, usize) -> i32;
    for call in &inits[..count as usize] {
        let entry: Entry = unsafe { core::mem::transmute(call.routine as usize) };
        unsafe { entry(call.module, 1, 0); }
    }
    unsafe { *module_out = base; }
    status::SUCCESS
}

/// LdrGetProcedureAddress: counted ANSI_STRING or ordinal. There is no
/// dependency on kernel32; this resolves against the same per-process PE
/// export table used by GetProcAddress.
#[no_mangle]
pub unsafe extern "system" fn LdrGetProcedureAddress(
    module: u64,
    name: *const UnicodeString,
    ordinal: u32,
    out: *mut usize,
) -> NtStatus {
    if out.is_null() { return status::INVALID_PARAMETER; }
    let mut buffer = [0u8; 257];
    let lookup = if name.is_null() {
        if ordinal > 0xffff { return status::INVALID_PARAMETER; }
        ordinal as usize as *const u8
    } else {
        let text = unsafe { &*name };
        if text.buffer.is_null() || text.length as usize >= buffer.len() { return status::INVALID_PARAMETER; }
        unsafe { core::ptr::copy_nonoverlapping(text.buffer as *const u8, buffer.as_mut_ptr(), text.length as usize); }
        buffer[text.length as usize] = 0;
        buffer.as_ptr()
    };
    let resolve: unsafe extern "system" fn(u64, *const u8, *mut u64) -> NtStatus =
        unsafe { core::mem::transmute(crate::VeilGetProcAddress as usize) };
    let mut address = 0u64;
    let s = unsafe { resolve(module, lookup, &mut address) };
    if status::is_success(s) { unsafe { *out = address as usize; } }
    s
}
