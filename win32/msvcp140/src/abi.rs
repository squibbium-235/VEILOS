//! Microsoft STL (x64) data layouts and imports from VEILOS kernel32.dll.
use core::ffi::c_void;

pub type Handle = usize;
pub type Bool = i32;

pub const SUCCESS: i32 = 0;
pub const NOMEM: i32 = 1;
pub const TIMEDOUT: i32 = 2;
pub const BUSY: i32 = 3;
pub const ERROR: i32 = 4;
pub const INFINITE: u32 = u32::MAX;
pub const MTX_PLAIN: i32 = 1;
pub const MTX_RECURSIVE: i32 = 0x100;

// MSVC's _Mtx_internal_imp_t, __msvc_threads_core.hpp, Windows x64.
#[repr(C)]
pub struct Mtx {
    pub kind: i32,
    pub _pad: i32,
    pub legacy_slot: usize,
    pub srw: usize,
    pub _reserved: [u8; 48],
    pub owner: i32,
    pub count: i32,
}

// MSVC's _Cnd_internal_imp_t, Windows x64.
#[repr(C)]
pub struct Cnd {
    pub legacy_slot: usize,
    pub cv: usize,
    pub _reserved: [u8; 56],
}

// By-value MSVC _Thrd_t has 16-byte size and an 8-byte handle.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Thrd {
    pub handle: Handle,
    pub id: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Timespec64 {
    pub sec: i64,
    pub nsec: i32, // Windows long is 32-bit even on x64.
    pub _pad: i32,
}

#[repr(C)]
#[derive(Default)]
pub struct Filetime {
    pub low: u32,
    pub high: u32,
}

// Compile-time ABI checks; these are part of the DLL's public contract.
const _: [(); 80] = [(); core::mem::size_of::<Mtx>()];
const _: [(); 72] = [(); core::mem::size_of::<Cnd>()];
const _: [(); 16] = [(); core::mem::size_of::<Thrd>()];
const _: [(); 16] = [(); core::mem::size_of::<Timespec64>()];
const _: [(); 16] = [(); core::mem::offset_of!(Mtx, srw)];
const _: [(); 72] = [(); core::mem::offset_of!(Mtx, owner)];

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    pub fn AcquireSRWLockExclusive(lock: *mut usize);
    pub fn AcquireSRWLockShared(lock: *mut usize);
    pub fn TryAcquireSRWLockExclusive(lock: *mut usize) -> u8;
    pub fn TryAcquireSRWLockShared(lock: *mut usize) -> u8;
    pub fn ReleaseSRWLockExclusive(lock: *mut usize);
    pub fn ReleaseSRWLockShared(lock: *mut usize);
    pub fn InitializeSRWLock(lock: *mut usize);
    pub fn InitializeConditionVariable(cv: *mut usize);
    pub fn SleepConditionVariableSRW(
        cv: *mut usize, lock: *mut usize, ms: u32, flags: u32,
    ) -> Bool;
    pub fn WakeConditionVariable(cv: *mut usize);
    pub fn WakeAllConditionVariable(cv: *mut usize);
    pub fn GetCurrentThreadId() -> u32;
    pub fn GetProcessHeap() -> Handle;
    pub fn HeapAlloc(heap: Handle, flags: u32, size: usize) -> *mut c_void;
    pub fn HeapFree(heap: Handle, flags: u32, ptr: *mut c_void) -> Bool;
    pub fn Sleep(ms: u32);
    pub fn SwitchToThread() -> Bool;
    pub fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
    pub fn CloseHandle(handle: Handle) -> Bool;
    pub fn GetExitCodeThread(handle: Handle, code: *mut u32) -> Bool;
    pub fn CreateThread(
        sa: *mut c_void, stack: usize,
        start: Option<unsafe extern "system" fn(*mut c_void) -> u32>,
        parameter: *mut c_void, flags: u32, tid: *mut u32,
    ) -> Handle;
    pub fn GetSystemInfo(info: *mut c_void);
    pub fn GetSystemTimeAsFileTime(out: *mut Filetime);
}
