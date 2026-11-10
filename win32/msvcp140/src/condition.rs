//! Microsoft STL condition variables, backed by VEILOS kernel32 SRW waits.
use core::{ffi::c_void, ptr};
use crate::abi::*;
use crate::mutex::{_Mtx_clear_owner, _Mtx_reset_owner};

#[no_mangle]
pub unsafe extern "system" fn _Cnd_init_in_situ(cnd: *mut Cnd) {
    if cnd.is_null() { return; }
    unsafe {
        (*cnd).legacy_slot = 0;
        InitializeConditionVariable(ptr::addr_of_mut!((*cnd).cv));
    }
}

#[no_mangle]
pub extern "system" fn _Cnd_destroy_in_situ(_cnd: *mut Cnd) {}

#[no_mangle]
pub unsafe extern "system" fn _Cnd_init(out: *mut *mut Cnd) -> i32 {
    if out.is_null() { return ERROR; }
    unsafe {
        *out = ptr::null_mut();
        let cnd = HeapAlloc(GetProcessHeap(), 8, core::mem::size_of::<Cnd>()) as *mut Cnd;
        if cnd.is_null() { return NOMEM; }
        _Cnd_init_in_situ(cnd);
        *out = cnd;
    }
    SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn _Cnd_destroy(cnd: *mut Cnd) {
    if !cnd.is_null() {
        unsafe { HeapFree(GetProcessHeap(), 0, cnd as *mut c_void); }
    }
}

unsafe fn wait_ms(cnd: *mut Cnd, mtx: *mut Mtx, ms: u32) -> i32 {
    if cnd.is_null() || mtx.is_null() { return ERROR; }
    unsafe {
        // CV waits atomically release and reacquire exactly one SRW ownership.
        if (*mtx).count != 1 || (*mtx).owner as u32 != GetCurrentThreadId() {
            return ERROR;
        }
        _Mtx_clear_owner(mtx);
        let ok = SleepConditionVariableSRW(
            ptr::addr_of_mut!((*cnd).cv),
            ptr::addr_of_mut!((*mtx).srw),
            ms, 0,
        );
        _Mtx_reset_owner(mtx);
        if ok != 0 { SUCCESS }
        else if ms == INFINITE { ERROR }
        else { TIMEDOUT }
    }
}

#[no_mangle]
pub unsafe extern "system" fn _Cnd_wait(cnd: *mut Cnd, mtx: *mut Mtx) -> i32 {
    unsafe { wait_ms(cnd, mtx, INFINITE) }
}

#[no_mangle]
pub unsafe extern "system" fn _Cnd_timedwait(cnd: *mut Cnd, mtx: *mut Mtx, t: *const Timespec64) -> i32 {
    unsafe { wait_ms(cnd, mtx, crate::time::until_ms(t)) }
}

#[no_mangle]
pub unsafe extern "system" fn _Cnd_signal(cnd: *mut Cnd) -> i32 {
    if cnd.is_null() { return ERROR; }
    unsafe { WakeConditionVariable(ptr::addr_of_mut!((*cnd).cv)); }
    SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn _Cnd_broadcast(cnd: *mut Cnd) -> i32 {
    if cnd.is_null() { return ERROR; }
    unsafe { WakeAllConditionVariable(ptr::addr_of_mut!((*cnd).cv)); }
    SUCCESS
}
