//! VEILOS `kernel32.dll`: the Win32 base API, built on `ntdll.dll`.
//!
//! Functions not here yet are still provided by the kernel's built-in
//! kernel32 (the loader falls back to it for any name this DLL doesn't
//! export), so this grows one area at a time (WIN32_DESIGN.md).
//!
//!   lib.rs     handles, errors, console I/O, process exit
//!   time.rs    tick counts, performance counter, system time, Sleep
//!   mem.rs     virtual memory, heaps, Local/Global memory, system info
//!   file.rs    paths, files, directories, attributes, find
//!   env.rs     command line, environment variables
//!   sync.rs    critical sections, SRW locks, events, waits, TLS slots
//!   module.rs  module handles and names, LoadLibrary, GetProcAddress
//!   util.rs    string conversions and the process heap

#![no_std]

mod apc;
mod atom;
mod bun;
mod com;
mod compat_misc;
mod crypt;
mod console;
mod env;
mod legacy;
mod exception;
mod fiber;
mod iocp;
mod toolchain;
mod file;
mod locale;
mod mapping;
mod mem;
mod module;
mod pool;
mod path_compat;
mod process;
mod profile;
mod rare;
mod registry;
mod resource;
mod security_compat;
mod acl_entries;
mod support;
mod system;
mod sync;
mod time;
mod util;
mod wait;

use core::arch::asm;
use nt_abi::{layout, status, IoStatusBlock, NtStatus, ObjectAttributes, CURRENT_PROCESS};

pub(crate) type Handle = u64;
pub(crate) type Bool = i32;

pub(crate) const INVALID_HANDLE_VALUE: Handle = u64::MAX;
/// GetStdHandle's arguments: (DWORD)-10, -11, -12.
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn VeilReg(call: *mut nt_abi::reg::RegCall) -> i32;
    pub(crate) fn VeilNameObject(h: Handle, name: *const u16, kind: u64) -> i32;
    pub(crate) fn VeilOpenNamed(name: *const u16, kind: u64, out: *mut Handle) -> i32;
    pub(crate) fn VeilWaitAddress(addr: u64, compare: u64, size: u64, ms: u64) -> i32;
    pub(crate) fn VeilWakeAddress(addr: u64) -> i32;
    pub(crate) fn VeilPipe(op: u64, a: u64, b: u64, c: u64) -> i32;
    pub(crate) fn VeilMutex(op: u64, a: u64, b: u64) -> i32;
    pub(crate) fn VeilSysInfo(op: u64, out: u64, size: u64) -> i32;
    pub(crate) fn VeilMapView(file: Handle, offset: u64, size: u64, out: *mut u64, flags: u64) -> i32;
    pub(crate) fn VeilUnmapView(addr: u64) -> i32;
    pub(crate) fn NtTerminateProcess(process: Handle, status: NtStatus) -> NtStatus;
    pub(crate) fn NtWriteFile(file: Handle, event: Handle, apc: usize, apc_context: usize, iosb: *mut IoStatusBlock,
                              buffer: *const u8, length: u32, offset: *const i64, key: *const u32) -> NtStatus;
    pub(crate) fn NtReadFile(file: Handle, event: Handle, apc: usize, apc_context: usize, iosb: *mut IoStatusBlock,
                             buffer: *mut u8, length: u32, offset: *const i64, key: *const u32) -> NtStatus;
    pub(crate) fn NtClose(handle: Handle) -> NtStatus;
    pub(crate) fn NtDelayExecution(alertable: u8, interval: *const i64) -> NtStatus;
    pub(crate) fn NtAllocateVirtualMemory(process: Handle, base: *mut usize, zero_bits: usize, size: *mut usize, kind: u32, protect: u32) -> NtStatus;
    pub(crate) fn NtFreeVirtualMemory(process: Handle, base: *mut usize, size: *mut usize, kind: u32) -> NtStatus;
    pub(crate) fn NtProtectVirtualMemory(process: Handle, base: *mut usize, size: *mut usize, protect: u32, old: *mut u32) -> NtStatus;
    pub(crate) fn NtQueryVirtualMemory(process: Handle, base: usize, class: u32, info: *mut u8, length: usize, ret: *mut usize) -> NtStatus;
    pub(crate) fn NtCreateFile(handle: *mut Handle, access: u32, attrs: *const ObjectAttributes, iosb: *mut IoStatusBlock,
                               allocation: *const i64, attributes: u32, share: u32, disposition: u32, options: u32,
                               ea: usize, ea_length: u32) -> NtStatus;
    pub(crate) fn NtQueryInformationFile(file: Handle, iosb: *mut IoStatusBlock, info: *mut u8, length: u32, class: u32) -> NtStatus;
    pub(crate) fn NtSetInformationFile(file: Handle, iosb: *mut IoStatusBlock, info: *const u8, length: u32, class: u32) -> NtStatus;
    pub(crate) fn NtQueryDirectoryFile(file: Handle, event: Handle, apc: usize, apc_context: usize, iosb: *mut IoStatusBlock,
                                       info: *mut u8, length: u32, class: u32, single: u8, mask: *const nt_abi::UnicodeString,
                                       restart: u8) -> NtStatus;
    pub(crate) fn NtQueryAttributesFile(attrs: *const ObjectAttributes, info: *mut u8) -> NtStatus;
    pub(crate) fn NtDeleteFile(attrs: *const ObjectAttributes) -> NtStatus;
    pub(crate) fn NtFlushBuffersFile(file: Handle, iosb: *mut IoStatusBlock) -> NtStatus;
    pub(crate) fn NtCreateEvent(handle: *mut Handle, access: u32, attrs: *const ObjectAttributes, kind: u32, initial: u8) -> NtStatus;
    pub(crate) fn NtSetEvent(event: Handle, previous: *mut i32) -> NtStatus;
    pub(crate) fn NtResetEvent(event: Handle, previous: *mut i32) -> NtStatus;
    pub(crate) fn NtWaitForSingleObject(handle: Handle, alertable: u8, timeout: *const i64) -> NtStatus;
    pub(crate) fn NtYieldExecution() -> NtStatus;
    pub(crate) fn LdrVeilTlsBegin();
    pub(crate) fn LdrVeilTlsEnd();
    pub(crate) fn VeilLoadDll(name: *const u16, chars: usize, base: *mut u64, inits: *mut nt_abi::InitCall, capacity: usize, count: *mut u32) -> NtStatus;
    pub(crate) fn VeilGetProcAddress(module: u64, name: *const u8, address: *mut u64) -> NtStatus;
    pub(crate) fn RtlNtStatusToDosError(status: NtStatus) -> u32;
    pub(crate) fn RtlCreateHeap(flags: u32, base: usize, reserve: usize, commit: usize, lock: usize, params: usize) -> usize;
    pub(crate) fn RtlDestroyHeap(heap: usize) -> usize;
    pub(crate) fn RtlAllocateHeap(heap: usize, flags: u32, size: usize) -> *mut u8;
    pub(crate) fn RtlFreeHeap(heap: usize, flags: u32, p: *mut u8) -> u8;
    pub(crate) fn RtlReAllocateHeap(heap: usize, flags: u32, p: *mut u8, size: usize) -> *mut u8;
    pub(crate) fn RtlSizeHeap(heap: usize, flags: u32, p: *mut u8) -> usize;
}

/// This thread's TEB.
pub(crate) fn teb() -> *mut u8 {
    let t: *mut u8;
    unsafe { asm!("mov {}, gs:[0x30]", out(reg) t, options(nostack, readonly, preserves_flags)) };
    t
}

pub(crate) fn peb() -> *mut u8 {
    unsafe { *(teb().add(layout::TEB_PEB) as *const *mut u8) }
}

pub(crate) fn process_parameters() -> *mut u8 {
    unsafe { *(peb().add(layout::PEB_PROCESS_PARAMETERS) as *const *mut u8) }
}

/// Record a failed NTSTATUS as this thread's last error; returns FALSE.
pub(crate) fn fail(status: NtStatus) -> Bool {
    SetLastError(unsafe { RtlNtStatusToDosError(status) });
    0
}

/// TRUE on success; otherwise the error is recorded and FALSE returned.
pub(crate) fn check(s: NtStatus) -> Bool {
    if status::is_success(s) { 1 } else { fail(s) }
}

#[no_mangle]
pub extern "system" fn GetLastError() -> u32 {
    unsafe { *(teb().add(layout::TEB_LAST_ERROR) as *const u32) }
}

#[no_mangle]
pub extern "system" fn SetLastError(code: u32) {
    unsafe { *(teb().add(layout::TEB_LAST_ERROR) as *mut u32) = code }
}

#[no_mangle]
pub extern "system" fn GetCurrentProcess() -> Handle {
    CURRENT_PROCESS
}

#[no_mangle]
pub extern "system" fn GetCurrentProcessId() -> u32 {
    unsafe { *(teb().add(layout::TEB_PROCESS_ID) as *const u64) as u32 }
}

#[no_mangle]
pub extern "system" fn GetCurrentThread() -> Handle {
    u64::MAX - 1
}

#[no_mangle]
pub extern "system" fn GetCurrentThreadId() -> u32 {
    unsafe { *(teb().add(layout::TEB_THREAD_ID) as *const u64) as u32 }
}

fn std_slot(which: u32) -> Option<usize> {
    match which {
        STD_INPUT_HANDLE => Some(layout::PARAMS_STD_INPUT),
        STD_OUTPUT_HANDLE => Some(layout::PARAMS_STD_OUTPUT),
        STD_ERROR_HANDLE => Some(layout::PARAMS_STD_ERROR),
        _ => None,
    }
}

#[no_mangle]
pub extern "system" fn GetStdHandle(which: u32) -> Handle {
    match std_slot(which) {
        Some(offset) => unsafe { *(process_parameters().add(offset) as *const Handle) },
        None => {
            SetLastError(6); // ERROR_INVALID_HANDLE
            INVALID_HANDLE_VALUE
        }
    }
}

#[no_mangle]
pub extern "system" fn SetStdHandle(which: u32, handle: Handle) -> Bool {
    match std_slot(which) {
        Some(offset) => {
            unsafe { *(process_parameters().add(offset) as *mut Handle) = handle };
            1
        }
        None => fail(status::INVALID_HANDLE),
    }
}

#[no_mangle]
pub unsafe extern "system" fn WriteFile(file: Handle, buffer: *const u8, length: u32, written: *mut u32, overlapped: usize) -> Bool {
    if !written.is_null() {
        unsafe { *written = 0 };
    }
    let mut iosb = IoStatusBlock::default();
    let offset = iocp::offset_of(overlapped);
    let s = unsafe { NtWriteFile(file, 0, 0, 0, &mut iosb, buffer, length, offset_ptr(&offset), core::ptr::null()) };
    iocp::complete(file, overlapped, s, iosb.information, true);
    if !status::is_success(s) {
        return fail(s);
    }
    if !written.is_null() {
        unsafe { *written = iosb.information as u32 };
    }
    1
}

// -----| named objects |-----

pub(crate) const KIND_EVENT: u64 = 1;
pub(crate) const KIND_MUTEX: u64 = 2;
pub(crate) const KIND_SEMAPHORE: u64 = 3;

/// Creating with a name that's taken: the object there (with
/// ERROR_ALREADY_EXISTS), or a failure if another kind holds the name.
pub(crate) fn named_existing(name: *const u16, kind: u64) -> Option<Handle> {
    if name.is_null() {
        return None;
    }
    let mut h: Handle = 0;
    match unsafe { VeilOpenNamed(name, kind, &mut h) } {
        0 => {
            SetLastError(183);
            Some(h)
        }
        s if s == status::OBJECT_NAME_NOT_FOUND => None,
        _ => {
            SetLastError(6); // ERROR_INVALID_HANDLE
            Some(0)
        }
    }
}

pub(crate) fn name_new(h: Handle, name: *const u16, kind: u64) {
    if !name.is_null() {
        unsafe { VeilNameObject(h, name, kind) };
    }
    SetLastError(0);
}

pub(crate) fn open_named(name: *const u16, kind: u64) -> Handle {
    let mut h: Handle = 0;
    match unsafe { VeilOpenNamed(name, kind, &mut h) } {
        0 => h,
        s if s == status::OBJECT_NAME_NOT_FOUND => {
            SetLastError(2);
            0
        }
        _ => {
            SetLastError(6);
            0
        }
    }
}

fn offset_ptr(offset: &Option<i64>) -> *const i64 {
    offset.as_ref().map_or(core::ptr::null(), |o| o)
}

/// Files: from the handle's position. Consoles: waits for a whole typed line
/// and returns it with its "\r\n" (or the first `length` bytes of it). End of
/// file or input reads 0 bytes and returns TRUE.
#[no_mangle]
pub unsafe extern "system" fn ReadFile(file: Handle, buffer: *mut u8, length: u32, read: *mut u32, overlapped: usize) -> Bool {
    if !read.is_null() {
        unsafe { *read = 0 };
    }
    // A pipe with nothing to read yet: pending, finished by a worker.
    if let Some(r) = iocp::read_pending(file, buffer, length, overlapped) {
        return r;
    }
    let mut iosb = IoStatusBlock::default();
    let offset = iocp::offset_of(overlapped);
    let s = unsafe { NtReadFile(file, 0, 0, 0, &mut iosb, buffer, length, offset_ptr(&offset), core::ptr::null()) };
    iocp::complete(file, overlapped, s, iosb.information, true);
    if s == status::END_OF_FILE {
        // With an OVERLAPPED the end of a file is an error; without, no bytes.
        return if overlapped != 0 { fail(s) } else { 1 };
    }
    if !status::is_success(s) {
        return fail(s);
    }
    if !read.is_null() {
        unsafe { *read = iosb.information as u32 };
    }
    1
}







#[no_mangle]
pub extern "system" fn GetConsoleCP() -> u32 {
    65001
}

#[no_mangle]
pub extern "system" fn GetConsoleOutputCP() -> u32 {
    65001
}

#[no_mangle]
pub extern "system" fn SetConsoleCP(_cp: u32) -> Bool {
    1
}

#[no_mangle]
pub extern "system" fn SetConsoleOutputCP(_cp: u32) -> Bool {
    1
}

#[no_mangle]
pub extern "system" fn CloseHandle(handle: Handle) -> Bool {
    // A file mapping lets go of its file (and contents) too.
    mapping::closed(handle);
    iocp::closed(handle);
    check(unsafe { NtClose(handle) })
}

#[no_mangle]
pub extern "system" fn ExitProcess(code: u32) -> ! {
    unsafe { NtTerminateProcess(CURRENT_PROCESS, code as NtStatus) };
    loop {}
}

#[no_mangle]
pub extern "system" fn DllMain(_module: usize, reason: u32, _reserved: usize) -> i32 {
    // DLL_PROCESS_ATTACH: VEILOS_MISSING_CALLS=zero asks for missing calls
    // to return 0 rather than end the program (src/subsystem.rs);
    // VEILOS_TRACE_SYSCALLS=1 logs this process's system calls.
    if reason == 1 {
        console::register_ctrl_routine();
        if env_is(b"VEILOS_MISSING_CALLS", b"zero") {
            unsafe { VeilSysInfo(2, 0, 0) };
        }
        if env_is(b"VEILOS_TRACE_SYSCALLS", b"1") {
            unsafe { VeilSysInfo(3, 0, 0) };
        }
        if env_is(b"VEILOS_TRACE_NET", b"1") {
            unsafe { VeilSysInfo(4, 0, 0) };
        }
    }
    1
}

/// Is environment variable `name` set to exactly `value`? (ASCII, short.)
fn env_is(name: &[u8], value: &[u8]) -> bool {
    let mut w = [0u16; 32];
    for (i, b) in name.iter().enumerate().take(31) {
        w[i] = *b as u16;
    }
    let mut got = [0u16; 8];
    let n = unsafe { crate::env::GetEnvironmentVariableW(w.as_ptr(), got.as_mut_ptr(), 8) } as usize;
    n == value.len() && got[..n].iter().map(|&c| c as u8).eq(value.iter().copied())
}

/// Stack probe (normally from the MSVC C runtime), called with the frame
/// size in RAX before a function allocates more than a page of stack: touch
/// each page from the caller's RSP down, so a guard page is never skipped.
/// Preserves every register (only R10/R11 may change, as MSVC's does).
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __chkstk() {
    core::arch::naked_asm!(
        "mov r10, rax",
        "lea r11, [rsp + 8]",      // the caller's RSP (above our return address)
        "2:",
        "cmp r10, 0x1000",
        "jb 3f",
        "sub r11, 0x1000",
        "test [r11], r11",
        "sub r10, 0x1000",
        "jmp 2b",
        "3:",
        "sub r11, r10",
        "test [r11], r11",
        "ret",
    )
}

/// Normally from the MSVC C runtime: marks that floating point is used.
#[no_mangle]
static _fltused: i32 = 0;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    ExitProcess(0xDEAD)
}
