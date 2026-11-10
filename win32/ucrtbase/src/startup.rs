//! Program start and end: argv and the environment, initialiser tables,
//! atexit, exit and abort, signals, and (until W5b) the exception entry
//! points.

use crate::convert::{to_narrow, to_wide};
use crate::string::{len, slice};
use crate::{heap, stdio, ExitProcess, GetCommandLineW, GetEnvironmentStringsW, SetEnvironmentVariableW, WriteFile};
use alloc::vec::Vec;

/// Write `msg` to stderr and end the process with `code`.
pub fn fatal(msg: &str, code: u32) -> ! {
    stdio::flush_all();
    let h = unsafe { crate::GetStdHandle(0xFFFF_FFF4) };
    let mut n = 0;
    unsafe {
        WriteFile(h, b"\r\n".as_ptr(), 2, &mut n, 0);
        WriteFile(h, msg.as_ptr(), msg.len() as u32, &mut n, 0);
        WriteFile(h, b"\r\n".as_ptr(), 2, &mut n, 0);
        ExitProcess(code)
    }
}

// -----| the command line |-----

#[no_mangle]
pub static mut __argc: i32 = 0;
#[no_mangle]
pub static mut __argv: *mut *mut u8 = core::ptr::null_mut();
#[no_mangle]
pub static mut __wargv: *mut *mut u16 = core::ptr::null_mut();
#[no_mangle]
pub static mut _environ: *mut *mut u8 = core::ptr::null_mut();
#[no_mangle]
pub static mut _wenviron: *mut *mut u16 = core::ptr::null_mut();
#[no_mangle]
pub static mut _acmdln: *mut u8 = core::ptr::null_mut();
#[no_mangle]
pub static mut _wcmdln: *mut u16 = core::ptr::null_mut();
#[no_mangle]
pub static mut _pgmptr: *mut u8 = core::ptr::null_mut();
#[no_mangle]
pub static mut _wpgmptr: *mut u16 = core::ptr::null_mut();

/// The command line split as the Microsoft C runtime does: spaces separate
/// arguments outside quotes; 2n backslashes before a quote are n and the
/// quote toggles quoting; 2n+1 are n and a literal quote; "" inside quotes
/// is a literal quote.
fn split_command_line(line: &[u16]) -> Vec<Vec<u16>> {
    let mut args = Vec::new();
    let mut i = 0;
    let q = b'"' as u16;
    let bs = b'\\' as u16;
    let is_space = |c: u16| c == b' ' as u16 || c == b'\t' as u16;
    // The program name: up to the next space, or quoted, with no escapes.
    let mut name = Vec::new();
    let mut quoted = false;
    while i < line.len() {
        let c = line[i];
        if c == q {
            quoted = !quoted;
        } else if is_space(c) && !quoted {
            break;
        } else {
            name.push(c);
        }
        i += 1;
    }
    args.push(name);
    loop {
        while i < line.len() && is_space(line[i]) {
            i += 1;
        }
        if i >= line.len() {
            break;
        }
        let mut arg = Vec::new();
        let mut quoted = false;
        while i < line.len() {
            let c = line[i];
            if c == bs {
                let mut n = 0;
                while i < line.len() && line[i] == bs {
                    n += 1;
                    i += 1;
                }
                if i < line.len() && line[i] == q {
                    arg.extend(core::iter::repeat_n(bs, n / 2));
                    if n % 2 == 1 {
                        arg.push(q);
                        i += 1;
                    }
                } else {
                    arg.extend(core::iter::repeat_n(bs, n));
                }
                continue;
            }
            if c == q {
                if quoted && i + 1 < line.len() && line[i + 1] == q {
                    arg.push(q);
                    i += 2;
                    continue;
                }
                quoted = !quoted;
                i += 1;
                continue;
            }
            if is_space(c) && !quoted {
                break;
            }
            arg.push(c);
            i += 1;
        }
        args.push(arg);
    }
    args
}

/// A null-terminated array of NUL-terminated copies (malloc'd, kept).
fn table<T: Copy>(items: impl Iterator<Item = *mut T>) -> *mut *mut T {
    let v: Vec<*mut T> = items.collect();
    let p = heap::malloc((v.len() + 1) * 8) as *mut *mut T;
    for (i, &x) in v.iter().enumerate() {
        unsafe { *p.add(i) = x };
    }
    unsafe { *p.add(v.len()) = core::ptr::null_mut() };
    p
}

fn wide_copy(s: &[u16]) -> *mut u16 {
    let p = heap::malloc((s.len() + 1) * 2) as *mut u16;
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
        *p.add(s.len()) = 0;
    }
    p
}

static mut ARGS_READY: bool = false;

fn set_up_args() {
    if unsafe { ARGS_READY } {
        return;
    }
    unsafe { ARGS_READY = true };
    let line = unsafe { GetCommandLineW() };
    let line = unsafe { slice(line) };
    let args = split_command_line(line);
    unsafe {
        __argc = args.len() as i32;
        __wargv = table(args.iter().map(|a| wide_copy(a)));
        __argv = table(args.iter().map(|a| to_narrow(a)));
        _wcmdln = wide_copy(line);
        _acmdln = to_narrow(line);
        // The program's full path, whatever its command line calls it: git works
        // out where it's installed from this, and runs itself as plain "git".
        let mut path = [0u16; 1024];
        let n = crate::GetModuleFileNameW(0, path.as_mut_ptr(), path.len() as u32) as usize;
        if n > 0 && n < path.len() {
            _wpgmptr = wide_copy(&path[..n]);
            _pgmptr = to_narrow(&path[..n]);
        } else {
            _wpgmptr = *__wargv;
            _pgmptr = *__argv;
        }
    }
}

static mut ENV_READY: bool = false;

fn set_up_environment() {
    if unsafe { ENV_READY } {
        return;
    }
    unsafe { ENV_READY = true };
    let block = unsafe { GetEnvironmentStringsW() };
    let mut entries: Vec<&[u16]> = Vec::new();
    if !block.is_null() {
        let mut p = block as *const u16;
        while unsafe { *p } != 0 {
            let s = unsafe { slice(p) };
            // "=C:=C:\dir" entries are the shell's, not the program's.
            if s[0] != b'=' as u16 {
                entries.push(s);
            }
            p = unsafe { p.add(s.len() + 1) };
        }
    }
    unsafe {
        _wenviron = table(entries.iter().map(|e| wide_copy(e)));
        _environ = table(entries.iter().map(|e| to_narrow(e)));
    }
}

#[no_mangle]
pub extern "C" fn _configure_narrow_argv(_mode: i32) -> i32 {
    set_up_args();
    0
}

#[no_mangle]
pub extern "C" fn _configure_wide_argv(_mode: i32) -> i32 {
    set_up_args();
    0
}

#[no_mangle]
pub extern "C" fn _initialize_narrow_environment() -> i32 {
    set_up_environment();
    0
}

#[no_mangle]
pub extern "C" fn _initialize_wide_environment() -> i32 {
    set_up_environment();
    0
}

#[no_mangle]
pub extern "C" fn _get_initial_narrow_environment() -> *mut *mut u8 {
    set_up_environment();
    unsafe { _environ }
}

#[no_mangle]
pub extern "C" fn _get_initial_wide_environment() -> *mut *mut u16 {
    set_up_environment();
    unsafe { _wenviron }
}

#[no_mangle]
pub extern "C" fn __p___argc() -> *mut i32 {
    set_up_args();
    &raw mut __argc
}

#[no_mangle]
pub extern "C" fn __p___argv() -> *mut *mut *mut u8 {
    set_up_args();
    &raw mut __argv
}

#[no_mangle]
pub extern "C" fn __p___wargv() -> *mut *mut *mut u16 {
    set_up_args();
    &raw mut __wargv
}

#[no_mangle]
pub extern "C" fn __p__environ() -> *mut *mut *mut u8 {
    set_up_environment();
    &raw mut _environ
}

#[no_mangle]
pub extern "C" fn __p__wenviron() -> *mut *mut *mut u16 {
    set_up_environment();
    &raw mut _wenviron
}

#[no_mangle]
pub extern "C" fn __p__acmdln() -> *mut *mut u8 {
    set_up_args();
    &raw mut _acmdln
}

#[no_mangle]
pub extern "C" fn __p__wcmdln() -> *mut *mut u16 {
    set_up_args();
    &raw mut _wcmdln
}

#[no_mangle]
pub extern "C" fn __p__pgmptr() -> *mut *mut u8 {
    set_up_args();
    &raw mut _pgmptr
}

#[no_mangle]
pub unsafe extern "C" fn _get_pgmptr(out: *mut *mut u8) -> i32 {
    set_up_args();
    unsafe { *out = _pgmptr };
    0
}

#[no_mangle]
pub unsafe extern "C" fn _get_wpgmptr(out: *mut *mut u16) -> i32 {
    set_up_args();
    unsafe { *out = _wpgmptr };
    0
}

/// msvcrt's startup: argc, argv and the environment in one call.
#[no_mangle]
pub unsafe extern "C" fn __getmainargs(argc: *mut i32, argv: *mut *mut *mut u8, env: *mut *mut *mut u8, _wildcard: i32, _info: *mut i32) -> i32 {
    set_up_args();
    set_up_environment();
    unsafe {
        *argc = __argc;
        *argv = __argv;
        *env = _environ;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn __wgetmainargs(argc: *mut i32, argv: *mut *mut *mut u16, env: *mut *mut *mut u16, _wildcard: i32, _info: *mut i32) -> i32 {
    set_up_args();
    set_up_environment();
    unsafe {
        *argc = __argc;
        *argv = __wargv;
        *env = _wenviron;
    }
    0
}

// -----| the environment |-----

/// The `_environ` entry for `name` (narrow), as an index.
unsafe fn find_env(name: &[u8]) -> Option<usize> {
    set_up_environment();
    let mut i = 0;
    loop {
        let e = unsafe { *_environ.add(i) };
        if e.is_null() {
            return None;
        }
        let s = unsafe { slice(e) };
        if s.len() > name.len() && s[name.len()] == b'=' && s[..name.len()].eq_ignore_ascii_case(name) {
            return Some(i);
        }
        i += 1;
    }
}

unsafe fn find_wenv(name: &[u16]) -> Option<usize> {
    set_up_environment();
    let mut i = 0;
    loop {
        let e = unsafe { *_wenviron.add(i) };
        if e.is_null() {
            return None;
        }
        let s = unsafe { slice(e) };
        if s.len() > name.len()
            && s[name.len()] == b'=' as u16
            && s[..name.len()].iter().zip(name).all(|(&a, &b)| crate::ctype::lower(a as u32) == crate::ctype::lower(b as u32))
        {
            return Some(i);
        }
        i += 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn getenv(name: *const u8) -> *mut u8 {
    let name = unsafe { slice(name) };
    match unsafe { find_env(name) } {
        Some(i) => unsafe { (*_environ.add(i)).add(name.len() + 1) },
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn _wgetenv(name: *const u16) -> *mut u16 {
    let name = unsafe { slice(name) };
    match unsafe { find_wenv(name) } {
        Some(i) => unsafe { (*_wenviron.add(i)).add(name.len() + 1) },
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn getenv_s(size: *mut usize, buf: *mut u8, cap: usize, name: *const u8) -> i32 {
    let v = unsafe { getenv(name) };
    if v.is_null() {
        unsafe {
            *size = 0;
            if cap > 0 && !buf.is_null() {
                *buf = 0;
            }
        }
        return 0;
    }
    let n = unsafe { len(v) } + 1;
    unsafe { *size = n };
    if buf.is_null() || cap == 0 {
        return 0;
    }
    if n > cap {
        return crate::errno::ERANGE;
    }
    unsafe { core::ptr::copy_nonoverlapping(v, buf, n) };
    0
}

#[no_mangle]
pub unsafe extern "C" fn _dupenv_s(out: *mut *mut u8, size: *mut usize, name: *const u8) -> i32 {
    let v = unsafe { getenv(name) };
    unsafe {
        if v.is_null() {
            *out = core::ptr::null_mut();
            if !size.is_null() {
                *size = 0;
            }
            return 0;
        }
        *out = crate::string::_strdup(v);
        if !size.is_null() {
            *size = len(v) + 1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _wdupenv_s(out: *mut *mut u16, size: *mut usize, name: *const u16) -> i32 {
    let v = unsafe { _wgetenv(name) };
    unsafe {
        if v.is_null() {
            *out = core::ptr::null_mut();
            if !size.is_null() {
                *size = 0;
            }
            return 0;
        }
        *out = crate::string::_wcsdup(v);
        if !size.is_null() {
            *size = len(v) + 1;
        }
    }
    0
}

/// Set (or with an empty value, remove) a variable in both tables and in
/// the process environment.
fn set_env(name: &[u16], value: &[u16]) -> i32 {
    set_up_environment();
    let wname = wide_copy(name);
    let wvalue = wide_copy(value);
    unsafe { SetEnvironmentVariableW(wname, if value.is_empty() { core::ptr::null() } else { wvalue }) };
    heap::free(wname as *mut u8);
    heap::free(wvalue as *mut u8);

    let mut wide: Vec<*mut u16> = Vec::new();
    let mut i = 0;
    loop {
        let e = unsafe { *_wenviron.add(i) };
        if e.is_null() {
            break;
        }
        wide.push(e);
        i += 1;
    }
    let found = unsafe { find_wenv(name) };
    let entry = if value.is_empty() {
        None
    } else {
        let mut v: Vec<u16> = name.to_vec();
        v.push(b'=' as u16);
        v.extend_from_slice(value);
        Some(wide_copy(&v))
    };
    match (found, entry) {
        (Some(k), Some(e)) => wide[k] = e,
        (Some(k), None) => {
            wide.remove(k);
        }
        (None, Some(e)) => wide.push(e),
        (None, None) => {}
    }
    unsafe {
        heap::free(_wenviron as *mut u8);
        heap::free(_environ as *mut u8);
        _wenviron = table(wide.iter().copied());
        _environ = table(wide.iter().map(|&w| to_narrow(slice(w))));
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _wputenv(assignment: *const u16) -> i32 {
    let s = unsafe { slice(assignment) };
    let Some(eq) = s.iter().position(|&c| c == b'=' as u16) else {
        crate::invalid_parameter();
        return -1;
    };
    set_env(&s[..eq], &s[eq + 1..])
}

#[no_mangle]
pub unsafe extern "C" fn _putenv(assignment: *const u8) -> i32 {
    let w = to_wide(unsafe { slice(assignment) });
    let r = unsafe { _wputenv(w) };
    heap::free(w as *mut u8);
    r
}

#[no_mangle]
pub unsafe extern "C" fn _wputenv_s(name: *const u16, value: *const u16) -> i32 {
    set_env(unsafe { slice(name) }, unsafe { slice(value) })
}

#[no_mangle]
pub unsafe extern "C" fn _putenv_s(name: *const u8, value: *const u8) -> i32 {
    let (n, v) = (to_wide(unsafe { slice(name) }), to_wide(unsafe { slice(value) }));
    let r = unsafe { _wputenv_s(n, v) };
    heap::free(n as *mut u8);
    heap::free(v as *mut u8);
    r
}

// -----| initialisers and atexit |-----

type Pvfv = Option<unsafe extern "C" fn()>;
type Pifv = Option<unsafe extern "C" fn() -> i32>;

#[no_mangle]
pub unsafe extern "C" fn _initterm(mut first: *const Pvfv, last: *const Pvfv) {
    while first < last {
        if let Some(f) = unsafe { *first } {
            unsafe { f() };
        }
        first = unsafe { first.add(1) };
    }
}

#[no_mangle]
pub unsafe extern "C" fn _initterm_e(mut first: *const Pifv, last: *const Pifv) -> i32 {
    while first < last {
        if let Some(f) = unsafe { *first } {
            let r = unsafe { f() };
            if r != 0 {
                return r;
            }
        }
        first = unsafe { first.add(1) };
    }
    0
}

/// UCRT's `_onexit_table_t`: a malloc'd array of functions, run last first.
#[repr(C)]
pub struct OnexitTable {
    first: *mut Pvfv,
    last: *mut Pvfv,
    end: *mut Pvfv,
}

static mut EXIT_TABLE: OnexitTable = OnexitTable { first: core::ptr::null_mut(), last: core::ptr::null_mut(), end: core::ptr::null_mut() };
static mut QUICK_EXIT_TABLE: OnexitTable = OnexitTable { first: core::ptr::null_mut(), last: core::ptr::null_mut(), end: core::ptr::null_mut() };

#[no_mangle]
pub unsafe extern "C" fn _initialize_onexit_table(t: *mut OnexitTable) -> i32 {
    if t.is_null() {
        return -1;
    }
    unsafe {
        if (*t).first.is_null() {
            (*t).last = core::ptr::null_mut();
            (*t).end = core::ptr::null_mut();
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _register_onexit_function(t: *mut OnexitTable, f: Pvfv) -> i32 {
    let t = unsafe { &mut *t };
    if t.last == t.end {
        let n = if t.first.is_null() { 0 } else { (t.last as usize - t.first as usize) / 8 };
        let cap = (n * 2).max(32);
        let p = heap::realloc(t.first as *mut u8, cap * 8) as *mut Pvfv;
        if p.is_null() {
            return -1;
        }
        t.first = p;
        t.last = unsafe { p.add(n) };
        t.end = unsafe { p.add(cap) };
    }
    unsafe {
        *t.last = f;
        t.last = t.last.add(1);
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn _execute_onexit_table(t: *mut OnexitTable) -> i32 {
    let t = unsafe { &mut *t };
    let (first, mut last) = (t.first, t.last);
    *t = OnexitTable { first: core::ptr::null_mut(), last: core::ptr::null_mut(), end: core::ptr::null_mut() };
    while !first.is_null() && last > first {
        last = unsafe { last.sub(1) };
        if let Some(f) = unsafe { *last } {
            unsafe { f() };
        }
    }
    heap::free(first as *mut u8);
    0
}

#[no_mangle]
pub unsafe extern "C" fn _crt_atexit(f: Pvfv) -> i32 {
    unsafe { _register_onexit_function(&raw mut EXIT_TABLE, f) }
}

#[no_mangle]
pub unsafe extern "C" fn atexit(f: Pvfv) -> i32 {
    unsafe { _crt_atexit(f) }
}

#[no_mangle]
pub unsafe extern "C" fn _onexit(f: Pvfv) -> Pvfv {
    if unsafe { _crt_atexit(f) } == 0 { f } else { None }
}

#[no_mangle]
pub unsafe extern "C" fn _crt_at_quick_exit(f: Pvfv) -> i32 {
    unsafe { _register_onexit_function(&raw mut QUICK_EXIT_TABLE, f) }
}

#[no_mangle]
pub unsafe extern "C" fn at_quick_exit(f: Pvfv) -> i32 {
    unsafe { _crt_at_quick_exit(f) }
}

/// msvcrt's atexit for DLLs: a table the DLL owns, as begin/end pointers.
#[no_mangle]
pub unsafe extern "C" fn __dllonexit(f: Pvfv, begin: *mut *mut Pvfv, end: *mut *mut Pvfv) -> Pvfv {
    let mut t = OnexitTable { first: unsafe { *begin }, last: unsafe { *end }, end: unsafe { *end } };
    if unsafe { _register_onexit_function(&mut t, f) } != 0 {
        return None;
    }
    unsafe {
        *begin = t.first;
        *end = t.last;
    }
    f
}

static mut TLS_ATEXIT: Option<unsafe extern "system" fn(usize, u32, usize)> = None;

#[no_mangle]
pub unsafe extern "C" fn _register_thread_local_exe_atexit_callback(f: Option<unsafe extern "system" fn(usize, u32, usize)>) {
    unsafe { TLS_ATEXIT = f };
}

static mut EXITING: bool = false;

/// atexit functions and stream flushing, once.
fn run_exit_handlers() {
    if unsafe { EXITING } {
        return;
    }
    unsafe { EXITING = true };
    if let Some(f) = unsafe { TLS_ATEXIT } {
        unsafe { f(0, 0, 0) }; // DLL_PROCESS_DETACH for thread_local destructors
    }
    unsafe { _execute_onexit_table(&raw mut EXIT_TABLE) };
    stdio::flush_all();
}

#[no_mangle]
pub extern "C" fn exit(code: i32) -> ! {
    run_exit_handlers();
    unsafe { ExitProcess(code as u32) }
}

#[no_mangle]
pub extern "C" fn _exit(code: i32) -> ! {
    unsafe { ExitProcess(code as u32) }
}

#[no_mangle]
pub extern "C" fn _Exit(code: i32) -> ! {
    unsafe { ExitProcess(code as u32) }
}

#[no_mangle]
pub extern "C" fn quick_exit(code: i32) -> ! {
    unsafe { _execute_onexit_table(&raw mut QUICK_EXIT_TABLE) };
    unsafe { ExitProcess(code as u32) }
}

#[no_mangle]
pub extern "C" fn _cexit() {
    run_exit_handlers();
}

#[no_mangle]
pub extern "C" fn _c_exit() {}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    if let Some(h) = handler(SIGABRT) {
        unsafe { h(SIGABRT) };
    }
    fatal("abnormal program termination", 3)
}

/// A failed assert() ends the program, saying which: it must never carry on.
fn assertion_failed(message: &str, file: &str, line: u32) -> ! {
    stdio::flush_all();
    let h = unsafe { crate::GetStdHandle(0xFFFF_FFF4) };
    let mut digits = [0u8; 10];
    let mut at = digits.len();
    let mut v = line;
    loop {
        at -= 1;
        digits[at] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let line = unsafe { core::str::from_utf8_unchecked(&digits[at..]) };
    for part in ["Assertion failed: ", message, ", file ", file, ", line ", line, "\r\n"] {
        let mut n = 0;
        unsafe { WriteFile(h, part.as_ptr(), part.len() as u32, &mut n, 0) };
    }
    abort()
}

#[no_mangle]
pub unsafe extern "C" fn _assert(message: *const u8, file: *const u8, line: u32) -> ! {
    let text = |p: *const u8| unsafe { core::str::from_utf8_unchecked(crate::string::slice(p)) };
    assertion_failed(text(message), text(file), line)
}

#[no_mangle]
pub extern "C" fn _set_abort_behavior(flags: u32, _mask: u32) -> u32 {
    flags
}

#[no_mangle]
pub extern "C" fn terminate() -> ! {
    abort()
}

#[export_name = "?terminate@@YAXXZ"]
pub extern "C" fn terminate_cpp() -> ! {
    abort()
}

#[no_mangle]
pub extern "C" fn _amsg_exit(n: i32) -> ! {
    let _ = n;
    fatal("runtime error", 255)
}

// MSVC's pure-virtual-call handler lives in the C runtime, shared with
// vcruntime140.dll through crt_forwarders.py. On x64 the handler is a single
// function pointer; saving it as usize avoids importing a second CRT.
use core::sync::atomic::{AtomicUsize, Ordering};

static PURECALL_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Register the application's pure-virtual-call callback, returning the old
/// callback (or null). MSVC declares _purecall_handler as void (__cdecl*)().
#[no_mangle]
pub extern "C" fn _set_purecall_handler(handler: usize) -> usize {
    PURECALL_HANDLER.swap(handler, Ordering::AcqRel)
}

#[no_mangle]
pub extern "C" fn _get_purecall_handler() -> usize {
    PURECALL_HANDLER.load(Ordering::Acquire)
}

#[no_mangle]
pub extern "C" fn _purecall() -> i32 {
    let handler = _get_purecall_handler();
    if handler != 0 {
        // The callback is an application-supplied MSVC __cdecl void(void).
        let callback: unsafe extern "C" fn() = unsafe { core::mem::transmute(handler) };
        unsafe { callback() };
    }
    // Microsoft terminates even if the registered handler returns.
    fatal("pure virtual function call", 3)
}

// -----| app type, matherr, misc. startup hooks |-----

static mut APP_TYPE: i32 = 0;

#[no_mangle]
pub extern "C" fn _set_app_type(t: i32) {
    unsafe { APP_TYPE = t };
}

#[no_mangle]
pub extern "C" fn __set_app_type(t: i32) {
    _set_app_type(t);
}

#[no_mangle]
pub extern "C" fn _query_app_type() -> i32 {
    unsafe { APP_TYPE }
}

#[no_mangle]
pub extern "C" fn __setusermatherr(_f: usize) {}

#[no_mangle]
pub extern "C" fn _setusermatherr(_f: usize) {}

#[no_mangle]
pub extern "C" fn _configthreadlocale(_mode: i32) -> i32 {
    2 // _DISABLE_PER_THREAD_LOCALE
}

#[no_mangle]
pub extern "C" fn _crt_debugger_hook(_n: i32) {}

#[no_mangle]
pub extern "C" fn __crtUnhandledException(_p: usize) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn _set_error_mode(_m: i32) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn __security_init_cookie() {}

/// msvcrt's numbered locks: one thread per process until W6.
#[no_mangle]
pub extern "C" fn _lock(_n: i32) {}

#[no_mangle]
pub extern "C" fn _unlock(_n: i32) {}

// -----| signals |-----

pub const SIGABRT: i32 = 22;
type Handler = unsafe extern "C" fn(i32);
static mut HANDLERS: [usize; 32] = [0; 32];

/// The program's handler for `sig` (not SIG_DFL 0 or SIG_IGN 1).
fn handler(sig: i32) -> Option<Handler> {
    let h = unsafe { HANDLERS[sig as usize & 31] };
    if h > 1 { Some(unsafe { core::mem::transmute::<usize, Handler>(h) }) } else { None }
}

#[no_mangle]
pub extern "C" fn signal(sig: i32, h: usize) -> usize {
    if !(1..32).contains(&sig) {
        crate::set_errno(crate::errno::EINVAL);
        return usize::MAX; // SIG_ERR
    }
    unsafe { core::mem::replace(&mut (*(&raw mut HANDLERS))[sig as usize], h) }
}

#[no_mangle]
pub extern "C" fn raise(sig: i32) -> i32 {
    if !(1..32).contains(&sig) {
        return -1;
    }
    let h = unsafe { HANDLERS[sig as usize] };
    match h {
        1 => 0,
        0 if sig == SIGABRT => abort(),
        0 => exit(3),
        _ => {
            unsafe { HANDLERS[sig as usize] = 0 };
            unsafe { core::mem::transmute::<usize, Handler>(h)(sig) };
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn __pxcptinfoptrs() -> *mut usize {
    static mut PTRS: usize = 0;
    &raw mut PTRS
}

// -----| exceptions (W5b) |-----

/// SEH filter for the startup code: let the exception go on.
#[no_mangle]
pub extern "C" fn _seh_filter_dll(_code: u32, _ptrs: usize) -> i32 {
    0 // EXCEPTION_CONTINUE_SEARCH
}

#[no_mangle]
pub extern "C" fn _seh_filter_exe(_code: u32, _ptrs: usize) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn _XcptFilter(_code: u32, _ptrs: usize) -> i32 {
    0
}

static mut CURRENT_EXCEPTION: usize = 0;
static mut CURRENT_CONTEXT: usize = 0;

#[no_mangle]
pub extern "C" fn __current_exception() -> *mut usize {
    &raw mut CURRENT_EXCEPTION
}

#[no_mangle]
pub extern "C" fn __current_exception_context() -> *mut usize {
    &raw mut CURRENT_CONTEXT
}

#[no_mangle]
pub extern "C" fn __std_terminate() -> ! {
    abort()
}

#[no_mangle]
pub extern "C" fn __telemetry_main_invoke_trigger(_p: usize) {}

#[no_mangle]
pub extern "C" fn __telemetry_main_return_trigger(_p: usize) {}

/// `__std_exception_data`: the what() string and whether it's owned.
#[repr(C)]
pub struct ExceptionData {
    what: *mut u8,
    owned: bool,
}

#[no_mangle]
pub unsafe extern "C" fn __std_exception_copy(from: *const ExceptionData, to: *mut ExceptionData) {
    unsafe {
        let from = &*from;
        if from.owned && !from.what.is_null() {
            *to = ExceptionData { what: crate::string::_strdup(from.what), owned: true };
        } else {
            *to = ExceptionData { what: from.what, owned: false };
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn __std_exception_destroy(d: *mut ExceptionData) {
    unsafe {
        if (*d).owned {
            heap::free((*d).what);
        }
        *d = ExceptionData { what: core::ptr::null_mut(), owned: false };
    }
}

/// `type_info` compare: by decorated name (offset 16 in type_info).
#[no_mangle]
pub unsafe extern "C" fn __std_type_info_compare(a: *const u8, b: *const u8) -> i32 {
    if a == b {
        return 0;
    }
    unsafe { crate::string::strcmp(a.add(16), b.add(16)) }
}

#[no_mangle]
pub unsafe extern "C" fn __std_type_info_hash(t: *const u8) -> usize {
    let mut h: usize = 0xcbf2_9ce4_8422_2325;
    for &b in unsafe { slice(t.add(16)) } {
        h = (h ^ b as usize).wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// The undecorated name: we give the decorated one.
#[no_mangle]
pub unsafe extern "C" fn __std_type_info_name(t: *const u8, _list: usize) -> *const u8 {
    unsafe { t.add(16) }
}

#[no_mangle]
pub extern "C" fn __std_type_info_destroy_list(_list: usize) {}

/// The command line after the program's name (what WinMain gets).
#[no_mangle]
pub unsafe extern "C" fn _get_wide_winmain_command_line() -> *const u16 {
    let mut p = unsafe { GetCommandLineW() };
    let quote = b'"' as u16;
    unsafe {
        if *p == quote {
            p = p.add(1);
            while *p != 0 && *p != quote {
                p = p.add(1);
            }
            if *p == quote {
                p = p.add(1);
            }
        } else {
            while *p > b' ' as u16 {
                p = p.add(1);
            }
        }
        while *p == b' ' as u16 || *p == 9 {
            p = p.add(1);
        }
    }
    p
}

/// Whether `c` starts a double-byte character: the C locale has none.
#[no_mangle]
pub extern "C" fn _ismbblead(_c: u32) -> i32 {
    0
}

/// After a stack overflow exception: nothing to restore, the guard page isn't
/// consumed here.
#[no_mangle]
pub extern "C" fn _resetstkoflw() -> i32 {
    1
}

/// `_o__get_narrow_winmain_command_line`'s plain name; see the wide one.
#[no_mangle]
pub unsafe extern "C" fn _get_narrow_winmain_command_line() -> *mut u8 {
    let mut p = unsafe { crate::GetCommandLineA() };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        // Past the program's name, then the spaces.
        let quoted = *p == b'"';
        if quoted {
            p = p.add(1);
        }
        while *p != 0 && (quoted && *p != b'"' || !quoted && *p > b' ') {
            p = p.add(1);
        }
        if quoted && *p == b'"' {
            p = p.add(1);
        }
        while *p != 0 && *p <= b' ' {
            p = p.add(1);
        }
    }
    p
}
