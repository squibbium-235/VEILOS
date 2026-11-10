//! malloc and friends, on the process heap (as the real CRT does since
//! VS2012). Aligned blocks keep the underlying pointer just below the
//! aligned address.

use crate::{errno, set_errno, GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc, HeapSize};

const HEAP_ZERO_MEMORY: u32 = 8;

fn heap() -> u64 {
    unsafe { GetProcessHeap() }
}

#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    let p = unsafe { HeapAlloc(heap(), 0, size.max(1)) };
    if p.is_null() {
        set_errno(errno::ENOMEM);
    }
    p
}

#[no_mangle]
pub extern "C" fn calloc(count: usize, size: usize) -> *mut u8 {
    let Some(total) = count.checked_mul(size) else {
        set_errno(errno::ENOMEM);
        return core::ptr::null_mut();
    };
    let p = unsafe { HeapAlloc(heap(), HEAP_ZERO_MEMORY, total.max(1)) };
    if p.is_null() {
        set_errno(errno::ENOMEM);
    }
    p
}

#[no_mangle]
pub extern "C" fn free(p: *mut u8) {
    if !p.is_null() {
        unsafe { HeapFree(heap(), 0, p) };
    }
}

#[no_mangle]
pub extern "C" fn realloc(p: *mut u8, size: usize) -> *mut u8 {
    if p.is_null() {
        return malloc(size);
    }
    if size == 0 {
        free(p);
        return core::ptr::null_mut();
    }
    let q = unsafe { HeapReAlloc(heap(), 0, p, size) };
    if q.is_null() {
        set_errno(errno::ENOMEM);
    }
    q
}

#[no_mangle]
pub extern "C" fn _msize(p: *mut u8) -> usize {
    unsafe { HeapSize(heap(), 0, p) }
}

/// realloc that zeroes the part beyond the old size.
#[no_mangle]
pub extern "C" fn _recalloc(p: *mut u8, count: usize, size: usize) -> *mut u8 {
    let Some(total) = count.checked_mul(size) else {
        set_errno(errno::ENOMEM);
        return core::ptr::null_mut();
    };
    let old = if p.is_null() { 0 } else { _msize(p) };
    let q = realloc(p, total);
    if !q.is_null() && total > old {
        unsafe { core::ptr::write_bytes(q.add(old), 0, total - old) };
    }
    q
}

#[no_mangle]
pub extern "C" fn _expand(_p: *mut u8, _size: usize) -> *mut u8 {
    core::ptr::null_mut() // can't grow in place: callers fall back to realloc
}

#[no_mangle]
pub extern "C" fn _aligned_malloc(size: usize, align: usize) -> *mut u8 {
    _aligned_offset_malloc(size, align, 0)
}

#[no_mangle]
pub extern "C" fn _aligned_offset_malloc(size: usize, align: usize, offset: usize) -> *mut u8 {
    if !align.is_power_of_two() {
        crate::invalid_parameter();
        return core::ptr::null_mut();
    }
    let align = align.max(8);
    let raw = malloc(size + align + 8);
    if raw.is_null() {
        return raw;
    }
    let aligned = ((raw as usize + 8 + offset + align - 1) & !(align - 1)) - offset;
    unsafe { *((aligned - 8) as *mut usize) = raw as usize };
    aligned as *mut u8
}

#[no_mangle]
pub extern "C" fn _aligned_free(p: *mut u8) {
    if !p.is_null() {
        free(unsafe { *((p as usize - 8) as *const usize) } as *mut u8);
    }
}

#[no_mangle]
pub extern "C" fn _aligned_realloc(p: *mut u8, size: usize, align: usize) -> *mut u8 {
    if p.is_null() {
        return _aligned_malloc(size, align);
    }
    if size == 0 {
        _aligned_free(p);
        return core::ptr::null_mut();
    }
    let raw = unsafe { *((p as usize - 8) as *const usize) } as *mut u8;
    let old = _msize(raw) - (p as usize - raw as usize);
    let q = _aligned_malloc(size, align);
    if !q.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(p, q, old.min(size)) };
        _aligned_free(p);
    }
    q
}

#[no_mangle]
pub extern "C" fn _aligned_msize(p: *mut u8, _align: usize, _offset: usize) -> usize {
    let raw = unsafe { *((p as usize - 8) as *const usize) } as *mut u8;
    _msize(raw) - (p as usize - raw as usize)
}

static mut NEW_MODE: i32 = 0;

#[no_mangle]
pub extern "C" fn _set_new_mode(mode: i32) -> i32 {
    unsafe { core::mem::replace(&mut *(&raw mut NEW_MODE), mode) }
}

#[no_mangle]
pub extern "C" fn _query_new_mode() -> i32 {
    unsafe { NEW_MODE }
}

/// The new handler, called by operator new on failure: none is installed.
#[no_mangle]
pub extern "C" fn _callnewh(_size: usize) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn _get_heap_handle() -> usize {
    heap() as usize
}

#[no_mangle]
pub extern "C" fn _heapchk() -> i32 {
    -2 // _HEAPOK
}

#[no_mangle]
pub extern "C" fn _heapmin() -> i32 {
    0
}


/// MSVC's internal heap helpers share the CRT process heap with calloc/free.
/// These are exported through the api-ms-win-crt-heap contract too.
#[no_mangle]
pub extern "C" fn _calloc_base(count: usize, size: usize) -> *mut u8 {
    calloc(count, size)
}

#[no_mangle]
pub extern "C" fn _free_base(p: *mut u8) {
    free(p)
}
