//! Threads, child processes and pipes (W6).
//!
//! CreateProcess finds the program as Windows does (the name as given, then
//! with ".exe", through the application's folder, the current directory,
//! the system folder and PATH), and gives it the caller's environment,
//! current directory and standard handles unless told otherwise. The
//! kernel loads it and hands back process and thread handles, which are
//! signalled when it ends.

use nt_abi::{status, NtStatus, ProcessParams, ProcessResult, ThreadResult, CURRENT_PROCESS};

use crate::util::{wstr, WBuf};
use crate::{check, fail, Bool, Handle};

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn VeilCreateThread(start: u64, param: u64, flags: u64, result: *mut ThreadResult) -> NtStatus;
    fn VeilCreateProcess(params: *const ProcessParams, result: *mut ProcessResult) -> NtStatus;
    fn VeilCreatePipe(read: *mut Handle, write: *mut Handle, size: u64) -> NtStatus;
    fn NtTerminateThread(thread: Handle, code: NtStatus) -> NtStatus;
    fn NtResumeThread(thread: Handle, previous: *mut u32) -> NtStatus;
    fn NtWaitForMultipleObjects(count: u32, handles: *const Handle, kind: u32, alertable: u8, timeout: *const i64) -> NtStatus;
    fn NtQueryInformationProcess(process: Handle, class: u32, info: *mut u8, length: u32, ret: *mut u32) -> NtStatus;
    fn NtQueryInformationThread(thread: Handle, class: u32, info: *mut u8, length: u32, ret: *mut u32) -> NtStatus;
    fn NtOpenProcess(out: *mut Handle, access: u32, attributes: *const u8, client_id: *const u64) -> NtStatus;
    fn NtDuplicateObject(src_process: Handle, src: Handle, dst_process: Handle, dst: *mut Handle, access: u32, attributes: u32, options: u32) -> NtStatus;
    fn RtlExitUserThread(code: u32) -> !;
}

const STILL_ACTIVE: u32 = 259;
const WAIT_FAILED: u32 = u32::MAX;
const WAIT_TIMEOUT: u32 = 258;

// -----| threads |-----

#[no_mangle]
pub unsafe extern "system" fn CreateThread(_sa: usize, stack: usize, start: u64, param: u64, flags: u32, tid: *mut u32) -> Handle {
    let mut r = ThreadResult::default();
    // The stack size in the upper half (0: the default).
    let s = unsafe { VeilCreateThread(start, param, flags as u64 | (stack as u64 >> 12) << 32, &mut r) };
    if s != status::SUCCESS {
        fail(s);
        return 0;
    }
    if !tid.is_null() {
        unsafe { *tid = r.tid as u32 };
    }
    r.handle
}

#[no_mangle]
pub unsafe extern "system" fn CreateRemoteThread(process: Handle, sa: usize, stack: usize, start: u64, param: u64, flags: u32, tid: *mut u32) -> Handle {
    if process != CURRENT_PROCESS {
        fail(status::ACCESS_DENIED);
        return 0;
    }
    unsafe { CreateThread(sa, stack, start, param, flags, tid) }
}

#[no_mangle]
pub extern "system" fn ExitThread(code: u32) -> ! {
    unsafe { RtlExitUserThread(code) }
}

#[no_mangle]
pub extern "system" fn TerminateThread(thread: Handle, code: u32) -> Bool {
    check(unsafe { NtTerminateThread(thread, code as NtStatus) })
}

#[no_mangle]
pub extern "system" fn ResumeThread(thread: Handle) -> u32 {
    let mut prev = 0;
    let s = unsafe { NtResumeThread(thread, &mut prev) };
    if s != status::SUCCESS {
        fail(s);
        return u32::MAX;
    }
    prev
}

/// Suspending a running thread isn't supported: report it as not suspended.
#[no_mangle]
pub extern "system" fn SuspendThread(_thread: Handle) -> u32 {
    0
}

/// THREAD_BASIC_INFORMATION: exit status, TEB, process and thread ids.
fn thread_info(thread: Handle) -> Option<[u64; 6]> {
    let mut info = [0u64; 6];
    let s = unsafe { NtQueryInformationThread(thread, 0, info.as_mut_ptr() as *mut u8, 48, core::ptr::null_mut()) };
    if s != status::SUCCESS {
        fail(s);
        return None;
    }
    Some(info)
}

/// PROCESS_BASIC_INFORMATION: exit status, PEB, affinity, priority, id, parent.
fn process_info(process: Handle) -> Option<[u64; 6]> {
    let mut info = [0u64; 6];
    let s = unsafe { NtQueryInformationProcess(process, 0, info.as_mut_ptr() as *mut u8, 48, core::ptr::null_mut()) };
    if s != status::SUCCESS {
        fail(s);
        return None;
    }
    Some(info)
}

#[no_mangle]
pub unsafe extern "system" fn GetExitCodeThread(thread: Handle, code: *mut u32) -> Bool {
    match thread_info(thread) {
        Some(i) => {
            let s = i[0] as u32;
            unsafe { *code = if s == status::PENDING as u32 { STILL_ACTIVE } else { s } };
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub extern "system" fn GetThreadId(thread: Handle) -> u32 {
    thread_info(thread).map_or(0, |i| i[3] as u32)
}

#[no_mangle]
pub extern "system" fn GetProcessIdOfThread(thread: Handle) -> u32 {
    thread_info(thread).map_or(0, |i| i[2] as u32)
}

#[no_mangle]
pub extern "system" fn GetThreadPriority(_thread: Handle) -> i32 {
    0 // THREAD_PRIORITY_NORMAL
}

#[no_mangle]
pub extern "system" fn SetThreadPriority(_thread: Handle, _priority: i32) -> Bool {
    1
}

#[no_mangle]
pub extern "system" fn SetThreadPriorityBoost(_thread: Handle, _disable: Bool) -> Bool {
    1
}

#[no_mangle]
pub extern "system" fn SetThreadAffinityMask(_thread: Handle, _mask: usize) -> usize {
    1
}

#[no_mangle]
pub unsafe extern "system" fn SetThreadDescription(_thread: Handle, _name: *const u16) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "system" fn GetThreadTimes(_t: Handle, created: *mut u64, exited: *mut u64, kernel: *mut u64, user: *mut u64) -> Bool {
    for p in [created, exited, kernel, user] {
        if !p.is_null() {
            unsafe { *p = 0 };
        }
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn GetProcessTimes(p: Handle, created: *mut u64, exited: *mut u64, kernel: *mut u64, user: *mut u64) -> Bool {
    unsafe { GetThreadTimes(p, created, exited, kernel, user) }
}

// -----| waiting |-----

#[no_mangle]
pub unsafe extern "system" fn WaitForMultipleObjectsEx(count: u32, handles: *const Handle, all: Bool, ms: u32, alertable: Bool) -> u32 {
    if alertable != 0 {
        return crate::apc::alertable(ms, |t| unsafe { WaitForMultipleObjectsEx(count, handles, all, t, 0) });
    }
    let timeout: i64 = -(ms as i64) * 10_000;
    let t = if ms == u32::MAX { core::ptr::null() } else { &timeout as *const i64 };
    let s = unsafe { NtWaitForMultipleObjects(count, handles, if all != 0 { 0 } else { 1 }, 0, t) };
    match s {
        status::TIMEOUT => WAIT_TIMEOUT,
        s if (0..64).contains(&s) => s as u32,
        s => {
            fail(s);
            WAIT_FAILED
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn WaitForMultipleObjects(count: u32, handles: *const Handle, all: Bool, ms: u32) -> u32 {
    unsafe { WaitForMultipleObjectsEx(count, handles, all, ms, 0) }
}

// -----| processes |-----

#[no_mangle]
pub unsafe extern "system" fn GetExitCodeProcess(process: Handle, code: *mut u32) -> Bool {
    match process_info(process) {
        Some(i) => {
            let s = i[0] as u32;
            unsafe { *code = if s == status::PENDING as u32 { STILL_ACTIVE } else { s } };
            1
        }
        None => 0,
    }
}

#[no_mangle]
pub extern "system" fn GetProcessId(process: Handle) -> u32 {
    process_info(process).map_or(0, |i| i[4] as u32)
}

#[no_mangle]
pub unsafe extern "system" fn QueryFullProcessImageNameW(
    process: Handle,
    flags: u32,
    name: *mut u16,
    size: *mut u32,
) -> Bool {
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const ERROR_NOT_SUPPORTED: u32 = 50;

    if name.is_null() || size.is_null() {
        crate::SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    // Initially support Win32 paths only.
    // PROCESS_NAME_NATIVE requires native NT paths.
    if flags != 0 {
        crate::SetLastError(ERROR_NOT_SUPPORTED);
        return 0;
    }

    // Support the current process, including a real handle
    // referring to that same process.
    if process != CURRENT_PROCESS {
        let pid = GetProcessId(process);

        if pid == 0 {
            return 0;
        }

        if pid != crate::GetCurrentProcessId() {
            crate::SetLastError(ERROR_NOT_SUPPORTED);
            return 0;
        }
    }

    let mut buffer = [0u16; 1024];

    let length = unsafe {
        crate::module::GetModuleFileNameW(
            0,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;

    if length == 0 {
        return 0;
    }

    if length >= buffer.len() {
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    let capacity = unsafe { *size } as usize;

    if capacity <= length {
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(
            buffer.as_ptr(),
            name,
            length + 1,
        );

        *size = length as u32;
    }

    1
}

#[no_mangle]
pub extern "system" fn TerminateProcess(process: Handle, code: u32) -> Bool {
    check(unsafe { crate::NtTerminateProcess(process, code as NtStatus) })
}

/// Is `path` an existing file (not a directory)?
fn is_file(path: &[u16]) -> bool {
    let mut b = WBuf::new();
    b.extend(path);
    let attrs = unsafe { crate::file::GetFileAttributesW(b.as_ptr()) };
    attrs != u32::MAX && attrs & 0x10 == 0
}

/// `name` made absolute in `out` (GetFullPathName).
fn full_path(name: &[u16], out: &mut WBuf) -> bool {
    let mut b = WBuf::new();
    b.extend(name);
    let n = unsafe { crate::file::GetFullPathNameW(b.as_ptr(), out.buf.len() as u32, out.buf.as_mut_ptr(), core::ptr::null_mut()) };
    if n == 0 || n as usize >= out.buf.len() {
        return false;
    }
    out.len = n as usize;
    true
}

fn ends_with_exe(name: &[u16]) -> bool {
    let n = name.len();
    n >= 4 && name[n - 4] == b'.' as u16 && crate::util::eq_ignore_case(&name[n - 3..], &[b'e' as u16, b'x' as u16, b'e' as u16])
}

/// Try `dir\name` (and with ".exe") as a program.
fn try_in(dir: &[u16], name: &[u16], out: &mut WBuf) -> bool {
    for ext in [false, true] {
        if ext && ends_with_exe(name) {
            continue;
        }
        let mut candidate = WBuf::new();
        candidate.extend(dir);
        if !dir.is_empty() && dir[dir.len() - 1] != b'\\' as u16 {
            candidate.push(b'\\' as u16);
        }
        candidate.extend(name);
        if ext {
            candidate.push_str(".exe");
        }
        let mut full = WBuf::new();
        if full_path(candidate.as_slice(), &mut full) && is_file(full.as_slice()) {
            *out = full;
            return true;
        }
    }
    false
}

/// Find the program `name` names: as a path if it has one, else through the
/// usual folders and PATH.
fn find_program(name: &[u16], out: &mut WBuf) -> bool {
    let has_path = name.iter().any(|&c| c == b'\\' as u16 || c == b'/' as u16 || c == b':' as u16);
    if has_path {
        return try_in(&[], name, out);
    }
    // The application's own folder.
    let mut exe = [0u16; 520];
    let n = unsafe { crate::module::GetModuleFileNameW(0, exe.as_mut_ptr(), exe.len() as u32) } as usize;
    if let Some(slash) = exe[..n].iter().rposition(|&c| c == b'\\' as u16) {
        if try_in(&exe[..slash], name, out) {
            return true;
        }
    }
    // The current directory, then the system folder.
    let mut cwd = [0u16; 520];
    let n = unsafe { crate::file::GetCurrentDirectoryW(cwd.len() as u32, cwd.as_mut_ptr()) } as usize;
    if try_in(&cwd[..n], name, out) {
        return true;
    }
    let system: [u16; 9] = [b'C' as u16, b':' as u16, b'\\' as u16, b'S' as u16, b'Y' as u16, b'S' as u16, b'T' as u16, b'E' as u16, b'M' as u16];
    if try_in(&system, name, out) {
        return true;
    }
    // PATH.
    let key: [u16; 5] = [b'P' as u16, b'A' as u16, b'T' as u16, b'H' as u16, 0];
    let mut path = [0u16; 2048];
    let n = unsafe { crate::env::GetEnvironmentVariableW(key.as_ptr(), path.as_mut_ptr(), path.len() as u32) } as usize;
    if n > 0 && n < path.len() {
        for dir in path[..n].split(|&c| c == b';' as u16).filter(|d| !d.is_empty()) {
            if try_in(dir, name, out) {
                return true;
            }
        }
    }
    false
}

/// The program name at the start of a command line: quoted, or up to the
/// first space.
fn first_token(line: &[u16]) -> &[u16] {
    let mut i = 0;
    while i < line.len() && (line[i] == b' ' as u16 || line[i] == b'\t' as u16) {
        i += 1;
    }
    let rest = &line[i..];
    if rest.first() == Some(&(b'"' as u16)) {
        let body = &rest[1..];
        let end = body.iter().position(|&c| c == b'"' as u16).unwrap_or(body.len());
        &body[..end]
    } else {
        let end = rest.iter().position(|&c| c == b' ' as u16 || c == b'\t' as u16).unwrap_or(rest.len());
        &rest[..end]
    }
}

const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
const CREATE_NEW_CONSOLE: u32 = 0x10;
const DETACHED_PROCESS: u32 = 0x8;
const STARTF_USESTDHANDLES: u32 = 0x100;

/// An ANSI environment block as UTF-16 (allocated; free with util::free).
unsafe fn widen_environment(env: *const u8) -> *mut u16 {
    let mut n = 0;
    while unsafe { *env.add(n) } != 0 || unsafe { *env.add(n + 1) } != 0 {
        n += 1;
    }
    n += 2;
    let out = crate::util::alloc(n * 2) as *mut u16;
    for i in 0..n {
        unsafe { *out.add(i) = *env.add(i) as u16 };
    }
    out
}

#[no_mangle]
pub unsafe extern "system" fn CreateProcessW(
    application: *const u16,
    command_line: *mut u16,
    _process_sa: usize,
    _thread_sa: usize,
    inherit: Bool,
    flags: u32,
    environment: *const u8,
    current_dir: *const u16,
    startup: *const u8,
    info: *mut u8,
) -> Bool {
    // The program.
    let mut image = WBuf::new();
    let found = if !application.is_null() {
        let name = unsafe { wstr(application) };
        try_in(&[], name, &mut image)
    } else if !command_line.is_null() {
        let line = unsafe { wstr(command_line) };
        find_program(first_token(line), &mut image)
    } else {
        false
    };
    if !found {
        crate::SetLastError(2); // ERROR_FILE_NOT_FOUND
        return 0;
    }

    // Its command line: as given, or the application name.
    let mut line = WBuf::new();
    if command_line.is_null() {
        line.push(b'"' as u16);
        line.extend(image.as_slice());
        line.push(b'"' as u16);
    }

    // Its current directory and environment: the caller's unless given.
    let mut cwd = WBuf::new();
    if current_dir.is_null() {
        let n = unsafe { crate::file::GetCurrentDirectoryW(cwd.buf.len() as u32, cwd.buf.as_mut_ptr()) };
        cwd.len = n as usize;
    } else {
        cwd.extend(unsafe { wstr(current_dir) });
    }
    let mut owned_env: *mut u16 = core::ptr::null_mut();
    let env: u64 = if environment.is_null() {
        owned_env = crate::env::GetEnvironmentStringsW();
        owned_env as u64
    } else if flags & CREATE_UNICODE_ENVIRONMENT != 0 {
        environment as u64
    } else {
        owned_env = unsafe { widen_environment(environment) };
        owned_env as u64
    };

    // Standard handles: those in STARTUPINFO, else (sharing the console)
    // the caller's own.
    let use_given = !startup.is_null() && unsafe { *(startup.add(60) as *const u32) } & STARTF_USESTDHANDLES != 0;
    let (std_handles, use_std) = if use_given {
        unsafe { ([*(startup.add(80) as *const u64), *(startup.add(88) as *const u64), *(startup.add(96) as *const u64)], 1) }
    } else if flags & (CREATE_NEW_CONSOLE | DETACHED_PROCESS) == 0 {
        (
            [crate::GetStdHandle(-10i32 as u32), crate::GetStdHandle(-11i32 as u32), crate::GetStdHandle(-12i32 as u32)],
            1,
        )
    } else {
        ([0; 3], 0)
    };

    // STARTUPINFOEX's attribute list: a pseudo-console to run in.
    let pseudo = if flags & EXTENDED_STARTUPINFO_PRESENT != 0 && !startup.is_null() {
        let list = unsafe { *(startup.add(104) as *const *const u8) };
        unsafe { attribute(list, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE) }.unwrap_or(0)
    } else {
        0
    };
    // There, the caller's console handles mean nothing: the program gets the
    // pseudo-console's (redirected ones pass on, as on Windows).
    let std_handles = if pseudo != 0 && !use_given {
        std_handles.map(|h| if crate::console::is_console_handle(h) { 0 } else { h })
    } else {
        std_handles
    };

    let params = ProcessParams {
        image: image.as_ptr() as u64,
        // As given, however long; `line` holds just the program's own name.
        command_line: if command_line.is_null() { line.as_ptr() as u64 } else { command_line as u64 },
        current_directory: if cwd.len > 0 { cwd.as_ptr() as u64 } else { 0 },
        environment: env,
        flags: flags as u64,
        std_handles: std_handles.map(|h| if h == crate::INVALID_HANDLE_VALUE { 0 } else { h }),
        use_std_handles: use_std,
        inherit_handles: (inherit != 0) as u64,
        startup_flags: if startup.is_null() { 0 } else { (unsafe { *(startup.add(60) as *const u32) }) as u64 },
        runtime_data: if startup.is_null() { 0 } else { unsafe { *(startup.add(72) as *const u64) } },
        runtime_size: if startup.is_null() { 0 } else { (unsafe { *(startup.add(66) as *const u16) }) as u64 },
        console: pseudo,
    };
    let mut result = ProcessResult::default();
    let s = unsafe { VeilCreateProcess(&params, &mut result) };
    if !owned_env.is_null() {
        if environment.is_null() {
            crate::env::FreeEnvironmentStringsW(owned_env);
        } else {
            crate::util::free(owned_env as *mut u8);
        }
    }
    if s != status::SUCCESS {
        return fail(s);
    }
    if !info.is_null() {
        unsafe {
            *(info as *mut u64) = result.process;
            *(info.add(8) as *mut u64) = result.thread;
            *(info.add(16) as *mut u32) = result.pid as u32;
            *(info.add(20) as *mut u32) = result.tid as u32;
        }
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn CreateProcessA(
    application: *const u8,
    command_line: *mut u8,
    process_sa: usize,
    thread_sa: usize,
    inherit: Bool,
    flags: u32,
    environment: *const u8,
    current_dir: *const u8,
    startup: *const u8,
    info: *mut u8,
) -> Bool {
    let app = (!application.is_null()).then(|| unsafe { crate::util::widen(application) });
    let mut line = (!command_line.is_null()).then(|| unsafe { crate::util::widen(command_line) });
    let dir = (!current_dir.is_null()).then(|| unsafe { crate::util::widen(current_dir) });
    unsafe {
        CreateProcessW(
            app.as_ref().map_or(core::ptr::null(), |a| a.as_ptr()),
            line.as_mut().map_or(core::ptr::null_mut(), |l| l.buf.as_mut_ptr()),
            process_sa,
            thread_sa,
            inherit,
            flags,
            environment,
            dir.as_ref().map_or(core::ptr::null(), |d| d.as_ptr()),
            startup,
            info,
        )
    }
}

/// STARTUPINFO for this process: the flags and C runtime data its parent
/// gave, and its standard handles.
#[no_mangle]
pub unsafe extern "system" fn GetStartupInfoW(info: *mut u8) {
    unsafe {
        use nt_abi::layout::{PARAMS_RUNTIME_DATA, PARAMS_WINDOW_FLAGS};
        let pp = crate::process_parameters();
        core::ptr::write_bytes(info, 0, 104);
        *(info as *mut u32) = 104;
        *(info.add(60) as *mut u32) = *(pp.add(PARAMS_WINDOW_FLAGS) as *const u32);
        *(info.add(66) as *mut u16) = *(pp.add(PARAMS_RUNTIME_DATA) as *const u16);
        *(info.add(72) as *mut u64) = *(pp.add(PARAMS_RUNTIME_DATA + 8) as *const u64);
        *(info.add(64) as *mut u16) = 1; // SW_SHOWNORMAL
        *(info.add(80) as *mut u64) = crate::GetStdHandle(-10i32 as u32);
        *(info.add(88) as *mut u64) = crate::GetStdHandle(-11i32 as u32);
        *(info.add(96) as *mut u64) = crate::GetStdHandle(-12i32 as u32);
    }
}

#[no_mangle]
pub unsafe extern "system" fn GetStartupInfoA(info: *mut u8) {
    unsafe { GetStartupInfoW(info) }
}

// -----| pipes and handles |-----

#[no_mangle]
pub unsafe extern "system" fn CreatePipe(read: *mut Handle, write: *mut Handle, sa: usize, size: u32) -> Bool {
    let ok = check(unsafe { VeilCreatePipe(read, write, size as u64) });
    if ok != 0 {
        unsafe {
            apply_inherit(*read, sa);
            apply_inherit(*write, sa);
        }
    }
    ok
}

/// A new handle goes to children only if its SECURITY_ATTRIBUTES ask. A pipe's
/// reader sees the end only once every write handle is closed, so a child
/// handed the write end of its own stdin would wait forever.
/// (Events, mutexes and the like still start out inheritable: a stray copy of
/// those changes nothing a program can see.)
pub fn apply_inherit(h: Handle, sa: usize) {
    // SECURITY_ATTRIBUTES: length, descriptor, bInheritHandle.
    let inherit = sa != 0 && unsafe { *((sa + 16) as *const u32) } != 0;
    SetHandleInformation(h, HANDLE_FLAG_INHERIT, if inherit { HANDLE_FLAG_INHERIT } else { 0 });
}

#[no_mangle]
pub unsafe extern "system" fn DuplicateHandle(
    src_process: Handle,
    src: Handle,
    dst_process: Handle,
    dst: *mut Handle,
    access: u32,
    inherit: Bool,
    options: u32,
) -> Bool {
    let attributes = if inherit != 0 { 2 } else { 0 }; // OBJ_INHERIT
    check(unsafe { NtDuplicateObject(src_process, src, dst_process, dst, access, attributes, options) })
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtSetInformationObject(h: Handle, class: u32, info: *const u8, length: u32) -> NtStatus;
    fn NtQueryObject(h: Handle, class: u32, info: *mut u8, length: u32, ret: *mut u32) -> NtStatus;
}

#[no_mangle]
pub unsafe extern "system" fn OpenProcess(access: u32, inherit: Bool, pid: u32) -> Handle {
    // OBJECT_ATTRIBUTES: its length, and Attributes at 24 (OBJ_INHERIT).
    let mut attributes = [0u8; 48];
    attributes[0] = 48;
    if inherit != 0 {
        attributes[24] = 2;
    }
    let client = [pid as u64, 0];
    let mut h: Handle = 0;
    let s = unsafe { NtOpenProcess(&mut h, access, attributes.as_ptr(), client.as_ptr()) };
    if s != status::SUCCESS {
        fail(s);
        return 0;
    }
    h
}

const HANDLE_FLAG_INHERIT: u32 = 1;

/// Whether CreateProcess(bInheritHandles) gives children this handle.
/// (Handles start out inheritable; ProtectFromClose isn't kept.)
#[no_mangle]
pub extern "system" fn SetHandleInformation(h: Handle, mask: u32, flags: u32) -> Bool {
    if mask & HANDLE_FLAG_INHERIT == 0 {
        return 1;
    }
    let info = [(flags & HANDLE_FLAG_INHERIT != 0) as u8, 0];
    check(unsafe { NtSetInformationObject(h, 4, info.as_ptr(), 2) })
}

#[no_mangle]
pub unsafe extern "system" fn GetHandleInformation(h: Handle, flags: *mut u32) -> Bool {
    let mut info = [0u8; 2];
    let s = unsafe { NtQueryObject(h, 4, info.as_mut_ptr(), 2, core::ptr::null_mut()) };
    if s != status::SUCCESS {
        return fail(s);
    }
    if !flags.is_null() {
        unsafe { *flags = info[0] as u32 };
    }
    1
}

/// Programs are looked for in the current directory too (unless
/// NoDefaultCurrentDirectoryInExePath is set, which VEILOS doesn't use).
#[no_mangle]
pub extern "system" fn NeedCurrentDirectoryForExePathW(_name: *const u16) -> Bool {
    1
}

#[no_mangle]
pub extern "system" fn NeedCurrentDirectoryForExePathA(_name: *const u8) -> Bool {
    1
}

// -----| process/thread attribute lists (STARTUPINFOEX) |-----
//
// Kept as given: a 24-byte header (room, used) and 24 bytes per attribute
// (number, size, value). Only the pseudo-console changes how VEILOS starts a
// program; the others (parent process, handle list, ...) are kept and unused.

const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;

/// An attribute's value in a list (the pointer-sized value itself).
unsafe fn attribute(list: *const u8, which: usize) -> Option<u64> {
    if list.is_null() {
        return None;
    }
    let used = unsafe { *(list.add(4) as *const u32) } as usize;
    (0..used).find_map(|i| unsafe {
        let e = list.add(24 + i * 24) as *const u64;
        (*e as usize == which).then(|| *e.add(2))
    })
}

#[no_mangle]
pub unsafe extern "system" fn InitializeProcThreadAttributeList(list: *mut u8, count: u32, _flags: u32, size: *mut usize) -> Bool {
    // Windows' size: a 24-byte header and 24 bytes per attribute.
    let need = 24 + count as usize * 24;
    if list.is_null() || unsafe { *size } < need {
        unsafe { *size = need };
        crate::SetLastError(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    unsafe {
        core::ptr::write_bytes(list, 0, need);
        *(list as *mut u32) = count;
    }
    1
}

#[no_mangle]
pub unsafe extern "system" fn UpdateProcThreadAttribute(list: *mut u8, _flags: u32, which: usize, value: *const u8, size: usize, _previous: *mut u8, _ret: *mut usize) -> Bool {
    if list.is_null() {
        crate::SetLastError(87);
        return 0;
    }
    let (room, used) = unsafe { (*(list as *const u32) as usize, *(list.add(4) as *const u32) as usize) };
    if used >= room {
        crate::SetLastError(122);
        return 0;
    }
    unsafe {
        let e = list.add(24 + used * 24) as *mut u64;
        *e = which as u64;
        *e.add(1) = size as u64;
        // lpValue as given: the HPCON itself, or the address of the value.
        *e.add(2) = value as u64;
        *(list.add(4) as *mut u32) = used as u32 + 1;
    }
    1
}

#[no_mangle]
pub extern "system" fn DeleteProcThreadAttributeList(_list: *mut u8) {}

// -----| debug output |-----

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn VeilDebugPrint(text: *const u8, length: usize) -> NtStatus;
}

/// OutputDebugString: to the kernel's log (there's no debugger to hear it).
#[no_mangle]
pub unsafe extern "system" fn OutputDebugStringA(text: *const u8) {
    if !text.is_null() {
        unsafe { VeilDebugPrint(text, crate::util::alen(text)) };
    }
}

#[no_mangle]
pub unsafe extern "system" fn OutputDebugStringW(text: *const u16) {
    if text.is_null() {
        return;
    }
    let mut out = [0u8; 1024];
    let mut n = 0;
    for &u in unsafe { wstr(text) } {
        if n < out.len() {
            out[n] = if u < 0x80 { u as u8 } else { b'?' };
            n += 1;
        }
    }
    unsafe { VeilDebugPrint(out.as_ptr(), n) };
}
