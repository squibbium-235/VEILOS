//! MSVC C11 thread compatibility entry points, backed by VEILOS kernel32.
use core::{ffi::c_void, ptr};
use crate::abi::*;

#[repr(C)]
struct ThreadStartArgs {
    callback: unsafe extern "C" fn(*mut c_void) -> i32,
    argument: *mut c_void,
}

unsafe extern "system" fn thread_entry(raw: *mut c_void) -> u32 {
    let args = unsafe { ptr::read(raw as *const ThreadStartArgs) };
    unsafe { HeapFree(GetProcessHeap(), 0, raw); }
    unsafe { (args.callback)(args.argument) as u32 }
}

#[no_mangle]
pub unsafe extern "system" fn _Thrd_create(
    out: *mut Thrd,
    callback: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    argument: *mut c_void,
) -> i32 {
    if out.is_null() || callback.is_none() { return ERROR; }
    unsafe {
        *out = Thrd { handle: 0, id: 0, _pad: 0 };
        let raw = HeapAlloc(GetProcessHeap(), 0, core::mem::size_of::<ThreadStartArgs>());
        if raw.is_null() { return NOMEM; }
        ptr::write(raw as *mut ThreadStartArgs, ThreadStartArgs {
            callback: callback.unwrap(), argument,
        });
        let handle = CreateThread(ptr::null_mut(), 0, Some(thread_entry), raw, 0, ptr::addr_of_mut!((*out).id));
        if handle == 0 {
            HeapFree(GetProcessHeap(), 0, raw);
            return ERROR;
        }
        (*out).handle = handle;
    }
    SUCCESS
}

#[no_mangle]
pub extern "system" fn _Thrd_id() -> u32 {
    unsafe { GetCurrentThreadId() }
}

#[no_mangle]
pub extern "system" fn _Thrd_yield() {
    unsafe { SwitchToThread(); }
}

#[no_mangle]
pub extern "system" fn _Thrd_hardware_concurrency() -> u32 {
    // sizeof(SYSTEM_INFO) is 48 bytes on Windows x64; dwNumberOfProcessors at +32.
    let mut info = [0u8; 64];
    unsafe {
        GetSystemInfo(info.as_mut_ptr() as *mut c_void);
        ptr::read_unaligned(info.as_ptr().add(32) as *const u32)
    }
}

#[no_mangle]
pub unsafe extern "system" fn _Thrd_join(thread: Thrd, exit: *mut i32) -> i32 {
    if thread.handle == 0 { return ERROR; }
    unsafe {
        if WaitForSingleObject(thread.handle, INFINITE) != 0 { return ERROR; }
        if !exit.is_null() {
            let mut code = 0u32;
            if GetExitCodeThread(thread.handle, &mut code) == 0 { return ERROR; }
            *exit = code as i32;
        }
        if CloseHandle(thread.handle) != 0 { SUCCESS } else { ERROR }
    }
}

#[no_mangle]
pub extern "system" fn _Thrd_detach(thread: Thrd) -> i32 {
    if thread.handle != 0 && unsafe { CloseHandle(thread.handle) } != 0 {
        SUCCESS
    } else { ERROR }
}

#[no_mangle]
pub extern "system" fn _Thrd_equal(a: Thrd, b: Thrd) -> i32 {
    (a.id == b.id) as i32
}

#[no_mangle]
pub extern "system" fn _Thrd_current() -> Thrd {
    Thrd { handle: 0, id: unsafe { GetCurrentThreadId() }, _pad: 0 }
}

#[no_mangle]
pub extern "system" fn _Thrd_sleep(until: *const Timespec64) {
    if until.is_null() { return; }
    loop {
        let ms = crate::time::until_ms(until);
        if ms == 0 { break; }
        unsafe { Sleep(ms); }
    }
}

#[no_mangle]
pub unsafe extern "system" fn _Smtx_lock_exclusive(lock: *mut usize) {
    unsafe { AcquireSRWLockExclusive(lock); }
}
#[no_mangle]
pub unsafe extern "system" fn _Smtx_lock_shared(lock: *mut usize) {
    unsafe { AcquireSRWLockShared(lock); }
}
#[no_mangle]
pub unsafe extern "system" fn _Smtx_try_lock_exclusive(lock: *mut usize) -> i32 {
    (unsafe { TryAcquireSRWLockExclusive(lock) } != 0) as i32
}
#[no_mangle]
pub unsafe extern "system" fn _Smtx_try_lock_shared(lock: *mut usize) -> i32 {
    (unsafe { TryAcquireSRWLockShared(lock) } != 0) as i32
}
#[no_mangle]
pub unsafe extern "system" fn _Smtx_unlock_exclusive(lock: *mut usize) {
    unsafe { ReleaseSRWLockExclusive(lock); }
}
#[no_mangle]
pub unsafe extern "system" fn _Smtx_unlock_shared(lock: *mut usize) {
    unsafe { ReleaseSRWLockShared(lock); }
}
