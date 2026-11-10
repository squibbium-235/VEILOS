//! VEILOS `ntdll.dll`: the bottom of the user-mode Windows stack.
//!
//! The `Nt*`/`Zw*` exports are system call stubs written exactly like
//! Windows' own (`mov r10, rcx; mov eax, ID; syscall; ret`), so arguments past
//! the fourth are where the kernel expects them on the caller's stack. The
//! numbers come from `nt_abi`. `Rtl*` helpers run entirely in user mode: the
//! heap (`heap.rs`) is created as the process heap when this DLL loads.

#![no_std]

mod exception;
mod heap;
mod rtl;
mod sec;
mod sync;
mod thread;

use core::arch::naked_asm;
use nt_abi::{layout, status, sys, NtStatus};

/// Export `$nt` and `$zw` as stubs for syscall `$id`.
macro_rules! syscall_stubs {
    ($($nt:ident, $zw:ident => $id:path;)*) => {$(
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "system" fn $nt() {
            naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const $id)
        }
        #[unsafe(naked)]
        #[no_mangle]
        pub unsafe extern "system" fn $zw() {
            naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const $id)
        }
    )*};
}

syscall_stubs! {
    NtTerminateProcess, ZwTerminateProcess => sys::NT_TERMINATE_PROCESS;
    NtWriteFile, ZwWriteFile => sys::NT_WRITE_FILE;
    NtClose, ZwClose => sys::NT_CLOSE;
    NtReadFile, ZwReadFile => sys::NT_READ_FILE;
    NtDelayExecution, ZwDelayExecution => sys::NT_DELAY_EXECUTION;
    NtProtectVirtualMemory, ZwProtectVirtualMemory => sys::NT_PROTECT_VIRTUAL_MEMORY;
    NtQueryVirtualMemory, ZwQueryVirtualMemory => sys::NT_QUERY_VIRTUAL_MEMORY;
    VeilNtCreateFileRaw, ZwVeilNtCreateFileRaw => sys::NT_CREATE_FILE;
    NtQueryInformationFile, ZwQueryInformationFile => sys::NT_QUERY_INFORMATION_FILE;
    NtSetInformationFile, ZwSetInformationFile => sys::NT_SET_INFORMATION_FILE;
    NtQueryDirectoryFile, ZwQueryDirectoryFile => sys::NT_QUERY_DIRECTORY_FILE;
    NtQueryAttributesFile, ZwQueryAttributesFile => sys::NT_QUERY_ATTRIBUTES_FILE;
    NtDeleteFile, ZwDeleteFile => sys::NT_DELETE_FILE;
    NtFlushBuffersFile, ZwFlushBuffersFile => sys::NT_FLUSH_BUFFERS_FILE;
    NtCreateEvent, ZwCreateEvent => sys::NT_CREATE_EVENT;
    NtSetEvent, ZwSetEvent => sys::NT_SET_EVENT;
    NtResetEvent, ZwResetEvent => sys::NT_RESET_EVENT;
    NtWaitForSingleObject, ZwWaitForSingleObject => sys::NT_WAIT_FOR_SINGLE_OBJECT;
    VeilLoadDll, ZwVeilLoadDll => sys::VEIL_LOAD_DLL;
    VeilGetProcAddress, ZwVeilGetProcAddress => sys::VEIL_GET_PROC_ADDRESS;
    NtWaitForMultipleObjects, ZwWaitForMultipleObjects => sys::NT_WAIT_FOR_MULTIPLE_OBJECTS;
    NtQueryInformationProcess, ZwQueryInformationProcess => sys::NT_QUERY_INFORMATION_PROCESS;
    NtQueryInformationThread, ZwQueryInformationThread => sys::NT_QUERY_INFORMATION_THREAD;
    NtResumeThread, ZwResumeThread => sys::NT_RESUME_THREAD;
    NtDuplicateObject, ZwDuplicateObject => sys::NT_DUPLICATE_OBJECT;
    NtOpenProcess, ZwOpenProcess => sys::NT_OPEN_PROCESS;
    VeilSocket, ZwVeilSocket => sys::VEIL_SOCKET;
    VeilConsole, ZwVeilConsole => sys::VEIL_CONSOLE;
    NtReadVirtualMemory, ZwReadVirtualMemory => sys::NT_READ_VIRTUAL_MEMORY;
    NtWriteVirtualMemory, ZwWriteVirtualMemory => sys::NT_WRITE_VIRTUAL_MEMORY;
    NtCreateSection, ZwCreateSection => sys::NT_CREATE_SECTION;
    NtMapViewOfSection, ZwMapViewOfSection => sys::NT_MAP_VIEW_OF_SECTION;
    NtUnmapViewOfSection, ZwUnmapViewOfSection => sys::NT_UNMAP_VIEW_OF_SECTION;
    NtCreateMutant, ZwCreateMutant => sys::NT_CREATE_MUTANT;
    NtCreateDirectoryObject, ZwCreateDirectoryObject => sys::NT_CREATE_DIRECTORY_OBJECT;
    NtOpenEvent, ZwOpenEvent => sys::NT_OPEN_EVENT;
    NtOpenMutant, ZwOpenMutant => sys::NT_OPEN_MUTANT;
    NtOpenSemaphore, ZwOpenSemaphore => sys::NT_OPEN_SEMAPHORE;
    NtOpenSection, ZwOpenSection => sys::NT_OPEN_SECTION;
    NtOpenDirectoryObject, ZwOpenDirectoryObject => sys::NT_OPEN_DIRECTORY_OBJECT;
    NtQueryEvent, ZwQueryEvent => sys::NT_QUERY_EVENT;
    NtQuerySemaphore, ZwQuerySemaphore => sys::NT_QUERY_SEMAPHORE;
    NtCreateTimer, ZwCreateTimer => sys::NT_CREATE_TIMER;
    NtSetTimer, ZwSetTimer => sys::NT_SET_TIMER;
    NtCancelTimer, ZwCancelTimer => sys::NT_CANCEL_TIMER;
    NtQueryTimer, ZwQueryTimer => sys::NT_QUERY_TIMER;
    NtAllocateVirtualMemoryEx, ZwAllocateVirtualMemoryEx => sys::NT_ALLOCATE_VIRTUAL_MEMORY_EX;
    NtCreateSymbolicLinkObject, ZwCreateSymbolicLinkObject => sys::NT_CREATE_SYMBOLIC_LINK_OBJECT;
    NtOpenSymbolicLinkObject, ZwOpenSymbolicLinkObject => sys::NT_OPEN_SYMBOLIC_LINK_OBJECT;
    NtQuerySymbolicLinkObject, ZwQuerySymbolicLinkObject => sys::NT_QUERY_SYMBOLIC_LINK_OBJECT;
    NtQueryVolumeInformationFile, ZwQueryVolumeInformationFile => sys::NT_QUERY_VOLUME_INFORMATION_FILE;
    VeilCreateThread, ZwVeilCreateThread => sys::VEIL_CREATE_THREAD;
    VeilCreateProcess, ZwVeilCreateProcess => sys::VEIL_CREATE_PROCESS;
    VeilCreatePipe, ZwVeilCreatePipe => sys::VEIL_CREATE_PIPE;
    NtSetInformationObject, ZwSetInformationObject => sys::NT_SET_INFORMATION_OBJECT;
    NtQueryObject, ZwQueryObject => sys::NT_QUERY_OBJECT;
    NtCreateSemaphore, ZwCreateSemaphore => sys::NT_CREATE_SEMAPHORE;
    NtReleaseSemaphore, ZwReleaseSemaphore => sys::NT_RELEASE_SEMAPHORE;
    VeilClipSet, ZwVeilClipSet => sys::VEIL_CLIP_SET;
    VeilClipGet, ZwVeilClipGet => sys::VEIL_CLIP_GET;
    VeilReg, ZwVeilReg => sys::VEIL_REG;
    VeilMapView, ZwVeilMapView => sys::VEIL_MAP_VIEW;
    VeilNameObject, ZwVeilNameObject => sys::VEIL_NAME_OBJECT;
    VeilOpenNamed, ZwVeilOpenNamed => sys::VEIL_OPEN_NAMED;
    VeilWaitAddress, ZwVeilWaitAddress => sys::VEIL_WAIT_ADDRESS;
    VeilWakeAddress, ZwVeilWakeAddress => sys::VEIL_WAKE_ADDRESS;
    VeilPipe, ZwVeilPipe => sys::VEIL_PIPE;
    VeilMutex, ZwVeilMutex => sys::VEIL_MUTEX;
    VeilSysInfo, ZwVeilSysInfo => sys::VEIL_SYSINFO;
    VeilUnmapView, ZwVeilUnmapView => sys::VEIL_UNMAP_VIEW;
    VeilUserCreateWindow, ZwVeilUserCreateWindow => sys::VEIL_USER_CREATE_WINDOW;
    VeilUserDestroyWindow, ZwVeilUserDestroyWindow => sys::VEIL_USER_DESTROY_WINDOW;
    VeilUserShowWindow, ZwVeilUserShowWindow => sys::VEIL_USER_SHOW_WINDOW;
    VeilUserSetText, ZwVeilUserSetText => sys::VEIL_USER_SET_TEXT;
    VeilUserSetPos, ZwVeilUserSetPos => sys::VEIL_USER_SET_POS;
    VeilUserGetPos, ZwVeilUserGetPos => sys::VEIL_USER_GET_POS;
    VeilUserPresent, ZwVeilUserPresent => sys::VEIL_USER_PRESENT;
    VeilUserPost, ZwVeilUserPost => sys::VEIL_USER_POST;
    VeilUserGetMessage, ZwVeilUserGetMessage => sys::VEIL_USER_GET_MESSAGE;
    VeilUserTimer, ZwVeilUserTimer => sys::VEIL_USER_TIMER;
    VeilUserQuery, ZwVeilUserQuery => sys::VEIL_USER_QUERY;
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn VeilDebugPrint(_text: *const u8, _len: usize) -> NtStatus {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::VEIL_DEBUG_PRINT)
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn ZwVeilDebugPrint(_text: *const u8, _len: usize) -> NtStatus {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::VEIL_DEBUG_PRINT)
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn NtTerminateThread(_thread: u64, _code: NtStatus) -> NtStatus {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::NT_TERMINATE_THREAD)
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn ZwTerminateThread(_thread: u64, _code: NtStatus) -> NtStatus {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::NT_TERMINATE_THREAD)
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn NtYieldExecution() -> NtStatus {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::NT_YIELD_EXECUTION)
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn ZwYieldExecution() -> NtStatus {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::NT_YIELD_EXECUTION)
}

// The heap calls these from Rust, so they are declared with their types.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn NtAllocateVirtualMemory(_process: u64, _base: *mut usize, _zero_bits: usize, _size: *mut usize, _kind: u32, _protect: u32) -> i32 {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::NT_ALLOCATE_VIRTUAL_MEMORY)
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn ZwAllocateVirtualMemory(_process: u64, _base: *mut usize, _zero_bits: usize, _size: *mut usize, _kind: u32, _protect: u32) -> i32 {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::NT_ALLOCATE_VIRTUAL_MEMORY)
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn NtFreeVirtualMemory(_process: u64, _base: *mut usize, _size: *mut usize, _kind: u32) -> i32 {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::NT_FREE_VIRTUAL_MEMORY)
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "system" fn ZwFreeVirtualMemory(_process: u64, _base: *mut usize, _size: *mut usize, _kind: u32) -> i32 {
    naked_asm!("mov r10, rcx", "mov eax, {id}", "syscall", "ret", id = const sys::NT_FREE_VIRTUAL_MEMORY)
}

/// The Win32 error code for an NTSTATUS (the common ones; anything else maps
/// to ERROR_MR_MID_NOT_FOUND, as Windows does for codes it doesn't know).
#[no_mangle]
pub extern "system" fn RtlNtStatusToDosError(s: NtStatus) -> u32 {
    match s {
        status::SUCCESS => 0,                   // ERROR_SUCCESS
        status::TIMEOUT => 258,                 // WAIT_TIMEOUT
        status::DISK_FULL => 112,               // ERROR_DISK_FULL
        s if s == 0xC000_00D4u32 as NtStatus => 17,  // STATUS_NOT_SAME_DEVICE
        s if s == 0xC000_00ACu32 as NtStatus => 231, // STATUS_PIPE_NOT_AVAILABLE: ERROR_PIPE_BUSY
        s if s == 0xC000_00B3u32 as NtStatus => 536, // STATUS_PIPE_LISTENING
        s if s == 0xC000_00B2u32 as NtStatus => 535, // STATUS_PIPE_CONNECTED
        s if s == 0xC000_00B5u32 as NtStatus => 121, // STATUS_IO_TIMEOUT: ERROR_SEM_TIMEOUT
        s if s == 0xC000_0046u32 as NtStatus => 288, // STATUS_MUTANT_NOT_OWNED: ERROR_NOT_OWNER
        s if s == 0xC000_0120u32 as NtStatus => 995, // STATUS_CANCELLED: ERROR_OPERATION_ABORTED
        status::NO_MORE_FILES => 18,            // ERROR_NO_MORE_FILES
        status::PARTIAL_COPY => 299,            // ERROR_PARTIAL_COPY
        status::NOT_IMPLEMENTED => 1,           // ERROR_INVALID_FUNCTION
        status::INVALID_INFO_CLASS => 87,       // ERROR_INVALID_PARAMETER
        status::INVALID_HANDLE => 6,            // ERROR_INVALID_HANDLE
        status::OBJECT_TYPE_MISMATCH => 6,      // ERROR_INVALID_HANDLE
        status::INVALID_PARAMETER => 87,        // ERROR_INVALID_PARAMETER
        status::ACCESS_VIOLATION => 998,        // ERROR_NOACCESS
        status::END_OF_FILE => 38,              // ERROR_HANDLE_EOF
        status::NO_MEMORY => 8,                 // ERROR_NOT_ENOUGH_MEMORY
        status::ACCESS_DENIED => 5,             // ERROR_ACCESS_DENIED
        status::BUFFER_TOO_SMALL => 122,        // ERROR_INSUFFICIENT_BUFFER
        status::OBJECT_NAME_INVALID => 123,     // ERROR_INVALID_NAME
        status::OBJECT_NAME_NOT_FOUND => 2,     // ERROR_FILE_NOT_FOUND
        status::OBJECT_NAME_COLLISION => 183,   // ERROR_ALREADY_EXISTS
        status::OBJECT_PATH_NOT_FOUND => 3,     // ERROR_PATH_NOT_FOUND
        status::FILE_IS_A_DIRECTORY => 5,       // ERROR_ACCESS_DENIED
        status::DIRECTORY_NOT_EMPTY => 145,     // ERROR_DIR_NOT_EMPTY
        status::NOT_A_DIRECTORY => 267,         // ERROR_DIRECTORY
        status::DLL_NOT_FOUND => 126,           // ERROR_MOD_NOT_FOUND
        status::PROCEDURE_NOT_FOUND => 127,     // ERROR_PROC_NOT_FOUND
        status::PIPE_BROKEN => 109,             // ERROR_BROKEN_PIPE
        status::INVALID_IMAGE_FORMAT => 193,    // ERROR_BAD_EXE_FORMAT
        status::PENDING => 997,                 // ERROR_IO_PENDING
        _ => 317,                               // ERROR_MR_MID_NOT_FOUND
    }
}

// -----| heap |-----

use heap::Heap;

#[no_mangle]
pub unsafe extern "system" fn RtlCreateHeap(_flags: u32, _base: usize, _reserve: usize, _commit: usize, _lock: usize, _params: usize) -> *mut Heap {
    unsafe { Heap::create() }
}

#[no_mangle]
pub unsafe extern "system" fn RtlDestroyHeap(heap: *mut Heap) -> *mut Heap {
    if !heap.is_null() {
        unsafe { Heap::destroy(heap) };
    }
    core::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "system" fn RtlAllocateHeap(heap: *mut Heap, flags: u32, size: usize) -> *mut u8 {
    if heap.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { (*heap).alloc(size, flags) }
}

#[no_mangle]
pub unsafe extern "system" fn RtlFreeHeap(heap: *mut Heap, _flags: u32, p: *mut u8) -> u8 {
    if p.is_null() {
        return 1;
    }
    if heap.is_null() {
        return 0;
    }
    unsafe { (*heap).free(p) as u8 }
}

#[no_mangle]
pub unsafe extern "system" fn RtlReAllocateHeap(heap: *mut Heap, flags: u32, p: *mut u8, size: usize) -> *mut u8 {
    if heap.is_null() {
        return core::ptr::null_mut();
    }
    if p.is_null() {
        return unsafe { (*heap).alloc(size, flags) };
    }
    unsafe { (*heap).realloc(p, size, flags) }
}

/// The size the block at `p` was allocated with, or (SIZE_T)-1.
#[no_mangle]
pub unsafe extern "system" fn RtlSizeHeap(_heap: *mut Heap, _flags: u32, p: *mut u8) -> usize {
    unsafe { Heap::size(p) }.unwrap_or(usize::MAX)
}

#[no_mangle]
pub extern "system" fn RtlValidateHeap(_heap: *mut Heap, _flags: u32, _p: *mut u8) -> u8 {
    1
}

/// This thread's TEB.
fn teb() -> *mut u8 {
    let t: *mut u8;
    unsafe { core::arch::asm!("mov {}, gs:[0x30]", out(reg) t, options(nostack, readonly, preserves_flags)) };
    t
}

/// Process attach (ntdll initialises before every other DLL): create the
/// process heap.
#[no_mangle]
pub extern "system" fn DllMain(_module: usize, reason: u32, _reserved: usize) -> i32 {
    if reason == 1 {
        unsafe {
            let peb = *(teb().add(layout::TEB_PEB) as *const *mut u8);
            *(peb.add(layout::PEB_PROCESS_HEAP) as *mut *mut Heap) = Heap::create();
            // PEB.FastPebLock: ntdll's own, as on Windows (sec.rs).
            *(peb.add(0x38) as *mut *mut u8) = sec::fast_peb_lock();
        }
    }
    1
}

/// Normally from the MSVC C runtime: marks that floating point is used.
#[no_mangle]
static _fltused: i32 = 0;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
