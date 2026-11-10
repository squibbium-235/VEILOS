//! Module handles and names (from PEB.Ldr), LoadLibrary and GetProcAddress
//! (through the kernel's loader, which also covers DLLs that exist only as
//! kernel built-ins).

use nt_abi::{layout, status, InitCall, UnicodeString};

use crate::util::{eq_ignore_case, narrow_out, wide_out, widen, wstr, WBuf};
use crate::{fail, Bool, Handle};

const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x4;

/// Each loaded module: (base, size, full name, base name).
fn modules(mut f: impl FnMut(u64, u32, &[u16], &[u16]) -> bool) {
    unsafe {
        let ldr = *(crate::peb().add(layout::PEB_LDR) as *const u64);
        let head = ldr + layout::LDR_IN_LOAD_ORDER as u64;
        let mut entry = *(head as *const u64);
        let mut guard = 0;
        while entry != head && entry != 0 && guard < 1024 {
            let base = *((entry + layout::LDR_ENTRY_DLL_BASE as u64) as *const u64);
            let size = *((entry + 0x40) as *const u32);
            let full = &*((entry + layout::LDR_ENTRY_FULL_NAME as u64) as *const UnicodeString);
            let short = &*((entry + layout::LDR_ENTRY_BASE_NAME as u64) as *const UnicodeString);
            let full = core::slice::from_raw_parts(full.buffer, full.length as usize / 2);
            let short = core::slice::from_raw_parts(short.buffer, short.length as usize / 2);
            if !f(base, size, full, short) {
                return;
            }
            entry = *(entry as *const u64);
            guard += 1;
        }
    }
}

fn image_base() -> u64 {
    unsafe { *(crate::peb().add(layout::PEB_IMAGE_BASE) as *const u64) }
}

/// The module called `name` ("kernel32", "KERNEL32.DLL", "C:\x\a.dll").
fn find(name: &[u16]) -> Option<u64> {
    let file = match name.iter().rposition(|&u| u == b'\\' as u16 || u == b'/' as u16) {
        Some(i) => &name[i + 1..],
        None => name,
    };
    let mut want = WBuf::new();
    want.extend(file);
    if !file.contains(&(b'.' as u16)) {
        want.push_str(".dll");
    }
    let mut found = None;
    modules(|base, _, _, short| {
        if eq_ignore_case(short, want.as_slice()) {
            found = Some(base);
            return false;
        }
        true
    });
    found
}

#[no_mangle]
pub unsafe extern "system" fn GetModuleHandleW(name: *const u16) -> Handle {
    if name.is_null() {
        return image_base();
    }
    match find(unsafe { wstr(name) }) {
        Some(b) => b,
        None => {
            crate::SetLastError(126); // ERROR_MOD_NOT_FOUND
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn GetModuleHandleA(name: *const u8) -> Handle {
    if name.is_null() {
        return image_base();
    }
    let w = unsafe { widen(name) };
    unsafe { GetModuleHandleW(w.as_ptr()) }
}

#[no_mangle]
pub unsafe extern "system" fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut Handle) -> Bool {
    let h = if flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 {
        let addr = name as u64;
        let mut found = 0;
        modules(|base, size, _, _| {
            if addr >= base && addr < base + size as u64 {
                found = base;
                return false;
            }
            true
        });
        found
    } else {
        unsafe { GetModuleHandleW(name) }
    };
    unsafe { *module = h };
    if h != 0 { 1 } else { fail(status::DLL_NOT_FOUND) }
}

#[no_mangle]
pub unsafe extern "system" fn GetModuleHandleExA(flags: u32, name: *const u8, module: *mut Handle) -> Bool {
    if flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS != 0 || name.is_null() {
        return unsafe { GetModuleHandleExW(flags, name as *const u16, module) };
    }
    let w = unsafe { widen(name) };
    unsafe { GetModuleHandleExW(flags, w.as_ptr(), module) }
}

/// The module's full path, truncated to `size` as Windows does (then
/// ERROR_INSUFFICIENT_BUFFER).
fn module_file_name(module: Handle, f: impl FnOnce(&[u16]) -> u32) -> u32 {
    let want = if module == 0 { image_base() } else { module };
    let mut name: Option<(*const u16, usize)> = None;
    modules(|base, _, full, _| {
        if base == want {
            name = Some((full.as_ptr(), full.len()));
            return false;
        }
        true
    });
    match name {
        Some((p, n)) => f(unsafe { core::slice::from_raw_parts(p, n) }),
        None => {
            crate::SetLastError(126);
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn GetModuleFileNameW(module: Handle, buffer: *mut u16, size: u32) -> u32 {
    module_file_name(module, |full| {
        if (size as usize) > full.len() {
            return unsafe { wide_out(full, buffer, size) };
        }
        if size > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(full.as_ptr(), buffer, size as usize - 1);
                *buffer.add(size as usize - 1) = 0;
            }
        }
        crate::SetLastError(122);
        size
    })
}

#[no_mangle]
pub unsafe extern "system" fn GetModuleFileNameA(module: Handle, buffer: *mut u8, size: u32) -> u32 {
    module_file_name(module, |full| {
        if (size as usize) > full.len() {
            return unsafe { narrow_out(full, buffer, size) };
        }
        if size > 0 {
            unsafe { narrow_out(&full[..size as usize - 1], buffer, size) };
        }
        crate::SetLastError(122);
        size
    })
}

type DllEntry = unsafe extern "system" fn(u64, u32, usize) -> i32;

#[no_mangle]
pub unsafe extern "system" fn LoadLibraryExW(name: *const u16, _file: Handle, _flags: u32) -> Handle {
    let name = unsafe { wstr(name) };
    if name.is_empty() {
        fail(status::INVALID_PARAMETER);
        return 0;
    }
    let mut base = 0u64;
    let mut inits = [InitCall::default(); 64];
    let mut count = 0u32;
    unsafe { crate::LdrVeilTlsBegin() };
    let s = unsafe { crate::VeilLoadDll(name.as_ptr(), name.len(), &mut base, inits.as_mut_ptr(), inits.len(), &mut count) };
    unsafe { crate::LdrVeilTlsEnd() };
    if !status::is_success(s) {
        fail(s);
        return 0;
    }
    // DllMain (and TLS callbacks) of what was just loaded, dependencies first.
    for call in &inits[..count as usize] {
        let entry: DllEntry = unsafe { core::mem::transmute(call.routine as usize) };
        unsafe { entry(call.module, 1, 0) };
    }
    base
}

#[no_mangle]
pub unsafe extern "system" fn LoadLibraryW(name: *const u16) -> Handle {
    unsafe { LoadLibraryExW(name, 0, 0) }
}

#[no_mangle]
pub unsafe extern "system" fn LoadLibraryExA(name: *const u8, file: Handle, flags: u32) -> Handle {
    let w = unsafe { widen(name) };
    unsafe { LoadLibraryExW(w.as_ptr(), file, flags) }
}

#[no_mangle]
pub unsafe extern "system" fn LoadLibraryA(name: *const u8) -> Handle {
    unsafe { LoadLibraryExA(name, 0, 0) }
}

/// `name` is a NUL-terminated name, or an ordinal below 0x10000.
#[no_mangle]
pub unsafe extern "system" fn GetProcAddress(module: Handle, name: *const u8) -> usize {
    let mut addr = 0u64;
    let s = unsafe { crate::VeilGetProcAddress(if module == 0 { image_base() } else { module }, name, &mut addr) };
    if status::is_success(s) {
        addr as usize
    } else {
        fail(s);
        0
    }
}

/// Modules stay loaded until the process exits.
#[no_mangle]
pub extern "system" fn FreeLibrary(_module: Handle) -> Bool {
    1
}

#[no_mangle]
pub extern "system" fn DisableThreadLibraryCalls(_module: Handle) -> Bool {
    1
}

#[no_mangle]
pub unsafe extern "system" fn SetDllDirectoryW(
    path: *const u16
) -> Bool {
    // VEILOS currently doesn't search the working directory.
    // Support the empty/default cases within its existing search model.
    if path.is_null() || unsafe { wstr(path) }.is_empty() {
        return 1;
    }

    // Custom DLL directories need kernel loader support.
    crate::SetLastError(120); // ERROR_CALL_NOT_IMPLEMENTED
    0
}

#[no_mangle]
pub unsafe extern "system" fn SetDllDirectoryA(
    path: *const u8
) -> Bool {
    if path.is_null() {
        return unsafe {
            SetDllDirectoryW(core::ptr::null())
        };
    }

    let wide = unsafe { widen(path) };
    unsafe { SetDllDirectoryW(wide.as_ptr()) }
}
