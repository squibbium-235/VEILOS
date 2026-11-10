//! MSVC _Mtx_* entry points using the Windows x64 _Mtx_internal_imp_t layout.
use core::ffi::c_void;
use core::ptr;
use crate::abi::*;

#[no_mangle]
pub unsafe extern "system" fn _Mtx_init_in_situ(mtx: *mut Mtx, kind: i32) {
    if mtx.is_null() { return; }
    unsafe {
        (*mtx).kind = kind;
        (*mtx).legacy_slot = 0;
        InitializeSRWLock(ptr::addr_of_mut!((*mtx).srw));
        (*mtx).owner = -1;
        (*mtx).count = 0;
    }
}

#[no_mangle]
pub extern "system" fn _Mtx_destroy_in_situ(_mtx: *mut Mtx) {}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_init(out: *mut *mut Mtx, kind: i32) -> i32 {
    if out.is_null() { return ERROR; }
    unsafe {
        *out = ptr::null_mut();
        let mtx = HeapAlloc(GetProcessHeap(), 8, core::mem::size_of::<Mtx>()) as *mut Mtx;
        if mtx.is_null() { return NOMEM; }
        _Mtx_init_in_situ(mtx, kind);
        *out = mtx;
    }
    SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_destroy(mtx: *mut Mtx) {
    if mtx.is_null() { return; }
    unsafe {
        _Mtx_destroy_in_situ(mtx);
        HeapFree(GetProcessHeap(), 0, mtx as *mut c_void);
    }
}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_current_owns(mtx: *const Mtx) -> i32 {
    if mtx.is_null() { return 0; }
    (unsafe { (*mtx).count > 0 && (*mtx).owner as u32 == GetCurrentThreadId() }) as i32
}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_lock(mtx: *mut Mtx) -> i32 {
    if mtx.is_null() { return ERROR; }
    unsafe {
        let tid = GetCurrentThreadId();
        if (*mtx).count > 0 && (*mtx).owner as u32 == tid {
            // Historical MSVC "plain" locks can reenter; typed locks require
            // MTX_RECURSIVE to allow reentry.
            if ((*mtx).kind & !MTX_RECURSIVE) != MTX_PLAIN
                && ((*mtx).kind & MTX_RECURSIVE) == 0
            {
                return BUSY;
            }
            (*mtx).count += 1;
            return SUCCESS;
        }
        AcquireSRWLockExclusive(ptr::addr_of_mut!((*mtx).srw));
        (*mtx).owner = tid as i32;
        (*mtx).count = 1;
    }
    SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_trylock(mtx: *mut Mtx) -> i32 {
    if mtx.is_null() { return ERROR; }
    unsafe {
        let tid = GetCurrentThreadId();
        if (*mtx).count > 0 && (*mtx).owner as u32 == tid {
            if (*mtx).kind & MTX_RECURSIVE == 0 { return BUSY; }
            (*mtx).count += 1;
            return SUCCESS;
        }
        if TryAcquireSRWLockExclusive(ptr::addr_of_mut!((*mtx).srw)) == 0 {
            return BUSY;
        }
        (*mtx).owner = tid as i32;
        (*mtx).count = 1;
    }
    SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_unlock(mtx: *mut Mtx) -> i32 {
    if mtx.is_null() { return ERROR; }
    unsafe {
        if (*mtx).count <= 0 || (*mtx).owner as u32 != GetCurrentThreadId() {
            return ERROR;
        }
        (*mtx).count -= 1;
        if (*mtx).count == 0 {
            (*mtx).owner = -1;
            ReleaseSRWLockExclusive(ptr::addr_of_mut!((*mtx).srw));
        }
    }
    SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_clear_owner(mtx: *mut Mtx) {
    if mtx.is_null() { return; }
    unsafe {
        (*mtx).owner = -1;
        if (*mtx).count > 0 { (*mtx).count -= 1; }
    }
}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_reset_owner(mtx: *mut Mtx) {
    if mtx.is_null() { return; }
    unsafe {
        (*mtx).owner = GetCurrentThreadId() as i32;
        (*mtx).count += 1;
    }
}

#[no_mangle]
pub unsafe extern "system" fn _Mtx_timedlock(mtx: *mut Mtx, target: *const Timespec64) -> i32 {
    if mtx.is_null() { return ERROR; }
    if target.is_null() { return unsafe { _Mtx_lock(mtx) }; }
    loop {
        let result = unsafe { _Mtx_trylock(mtx) };
        if result == SUCCESS || result == ERROR { return result; }
        if crate::time::until_ms(target) == 0 { return TIMEDOUT; }
        unsafe { Sleep(1) };
    }
}
