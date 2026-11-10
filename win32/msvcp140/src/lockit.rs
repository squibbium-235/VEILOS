//! std::_Lockit is a small MSVC STL runtime-wide lock helper.
use core::{ffi::c_void, sync::atomic::AtomicUsize};
use crate::abi::{AcquireSRWLockExclusive, ReleaseSRWLockExclusive};

static STL_LOCKS: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

#[export_name = "??0_Lockit@std@@QEAA@H@Z"]
pub unsafe extern "system" fn lockit_constructor(which: *mut c_void, index: i32) -> *mut c_void {
    if which.is_null() { return core::ptr::null_mut(); }
    let slot = (index as u32 as usize) % STL_LOCKS.len();
    unsafe {
        *(which as *mut i32) = slot as i32;
        AcquireSRWLockExclusive(STL_LOCKS[slot].as_ptr());
    }
    which
}

#[export_name = "??0_Lockit@std@@QEAA@XZ"]
pub unsafe extern "system" fn lockit_default_constructor(which: *mut c_void) -> *mut c_void {
    unsafe { lockit_constructor(which, 0) }
}

#[export_name = "??1_Lockit@std@@QEAA@XZ"]
pub unsafe extern "system" fn lockit_destructor(which: *mut c_void) {
    if which.is_null() { return; }
    let index = unsafe { *(which as *const i32) as u32 as usize } % STL_LOCKS.len();
    unsafe { ReleaseSRWLockExclusive(STL_LOCKS[index].as_ptr()); }
}
