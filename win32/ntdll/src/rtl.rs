//! Strings and paths (W7): UNICODE_STRING helpers, DOS paths to NT paths,
//! the version, NtOpenFile, and the token and process calls VEILOS answers
//! simply (no security tokens yet).

use core::ptr::read_unaligned;
use nt_abi::{layout, status, NtStatus};

#[repr(C)]
pub struct UnicodeString {
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    pub(crate) buffer: *mut u16,
}

fn heap() -> *mut crate::heap::Heap {
    let peb: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, readonly));
        read_unaligned((peb + 0x30) as *const u64) as *mut crate::heap::Heap
    }
}

unsafe fn wlen(p: *const u16) -> usize {
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

#[no_mangle]
pub unsafe extern "system" fn RtlInitUnicodeString(s: *mut UnicodeString, text: *const u16) {
    let n = if text.is_null() { 0 } else { unsafe { wlen(text) } };
    unsafe {
        *s = UnicodeString { length: (n * 2) as u16, maximum_length: if text.is_null() { 0 } else { (n * 2 + 2) as u16 }, buffer: text as *mut u16 };
    }
}

#[no_mangle]
pub unsafe extern "system" fn RtlInitUnicodeStringEx(s: *mut UnicodeString, text: *const u16) -> NtStatus {
    unsafe { RtlInitUnicodeString(s, text) };
    status::SUCCESS
}

/// ANSI_STRING has the same shape with bytes.
#[no_mangle]
pub unsafe extern "system" fn RtlInitAnsiString(s: *mut UnicodeString, text: *const u8) {
    let mut n = 0;
    if !text.is_null() {
        while unsafe { *text.add(n) } != 0 {
            n += 1;
        }
    }
    unsafe {
        *s = UnicodeString { length: n as u16, maximum_length: if text.is_null() { 0 } else { (n + 1) as u16 }, buffer: text as *mut u16 };
    }
}

/// A heap copy of `units` as a UNICODE_STRING (NUL-terminated).
unsafe fn make(s: *mut UnicodeString, units: impl Iterator<Item = u16> + Clone) -> bool {
    let n = units.clone().count();
    let buf = unsafe { crate::RtlAllocateHeap(heap(), 0, (n + 1) * 2) } as *mut u16;
    if buf.is_null() {
        return false;
    }
    for (i, u) in units.enumerate() {
        unsafe { *buf.add(i) = u };
    }
    unsafe {
        *buf.add(n) = 0;
        *s = UnicodeString { length: (n * 2) as u16, maximum_length: (n * 2 + 2) as u16, buffer: buf };
    }
    true
}

#[no_mangle]
pub unsafe extern "system" fn RtlCreateUnicodeString(s: *mut UnicodeString, text: *const u16) -> u8 {
    let n = unsafe { wlen(text) };
    unsafe { make(s, core::slice::from_raw_parts(text, n).iter().copied()) as u8 }
}

#[no_mangle]
pub unsafe extern "system" fn RtlCreateUnicodeStringFromAsciiz(s: *mut UnicodeString, text: *const u8) -> u8 {
    let mut n = 0;
    while unsafe { *text.add(n) } != 0 {
        n += 1;
    }
    unsafe { make(s, core::slice::from_raw_parts(text, n).iter().map(|&b| b as u16)) as u8 }
}

#[no_mangle]
pub unsafe extern "system" fn RtlFreeUnicodeString(s: *mut UnicodeString) {
    unsafe {
        if !(*s).buffer.is_null() {
            crate::RtlFreeHeap(heap(), 0, (*s).buffer as *mut u8);
        }
        *s = UnicodeString { length: 0, maximum_length: 0, buffer: core::ptr::null_mut() };
    }
}

#[no_mangle]
pub unsafe extern "system" fn RtlFreeAnsiString(s: *mut UnicodeString) {
    unsafe { RtlFreeUnicodeString(s) };
}

#[no_mangle]
pub extern "system" fn RtlFindLeastSignificantBit(set: u64) -> i8 {
    if set == 0 { -1 } else { set.trailing_zeros() as i8 }
}

#[no_mangle]
pub extern "system" fn RtlFindMostSignificantBit(set: u64) -> i8 {
    if set == 0 { -1 } else { 63 - set.leading_zeros() as i8 }
}

/// RTL_OSVERSIONINFOW: size, major, minor, build, platform, CSD.
#[no_mangle]
pub unsafe extern "system" fn RtlGetVersion(info: *mut u32) -> NtStatus {
    unsafe {
        let size = *info as usize;
        core::ptr::write_bytes((info as *mut u8).add(4), 0, size.saturating_sub(4));
        *info.add(1) = 10;
        *info.add(2) = 0;
        *info.add(3) = 19041;
        *info.add(4) = 2;
    }
    status::SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn RtlGetNtVersionNumbers(major: *mut u32, minor: *mut u32, build: *mut u32) {
    unsafe {
        if !major.is_null() {
            *major = 10;
        }
        if !minor.is_null() {
            *minor = 0;
        }
        if !build.is_null() {
            *build = 19041 | 0xF000_0000;
        }
    }
}

// -----| DOS paths to NT paths |-----

/// The current directory (with its trailing backslash), from the process
/// parameters.
fn current_directory() -> &'static [u16] {
    unsafe {
        let peb: u64;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, readonly));
        let pp = read_unaligned((peb + layout::PEB_PROCESS_PARAMETERS as u64) as *const u64);
        let us = pp + layout::PARAMS_CURRENT_DIRECTORY as u64;
        let len = read_unaligned(us as *const u16) as usize / 2;
        let buf = read_unaligned((us + 8) as *const u64) as *const u16;
        core::slice::from_raw_parts(buf, len)
    }
}

const SLASH: u16 = b'\\' as u16;

/// `dos` made absolute and normalised ("C:\dir\file"), in `out`. Returns
/// the length and where the last component starts.
pub(crate) fn full_dos_path(dos: &[u16], out: &mut [u16; 1024]) -> Option<(usize, usize)> {
    let mut n = 0;
    fn push(out: &mut [u16; 1024], u: u16, n: &mut usize) {
        if *n < out.len() - 1 {
            out[*n] = if u == b'/' as u16 { SLASH } else { u };
            *n += 1;
        }
    }
    let cwd = current_directory();
    let is_sep = |u: u16| u == SLASH || u == b'/' as u16;
    // The root ("C:\") and the rest.
    let rest: &[u16] = if dos.len() >= 2 && dos[1] == b':' as u16 {
        push(out, dos[0], &mut n);
        push(out, b':' as u16, &mut n);
        push(out, SLASH, &mut n);
        if dos.len() >= 3 && is_sep(dos[2]) {
            &dos[3..]
        } else {
            // "C:name": relative to the current directory if it's on C:.
            if cwd.len() > 3 && (cwd[0] | 0x20) == (dos[0] | 0x20) {
                for &u in &cwd[3..] {
                    push(out, u, &mut n);
                }
            }
            &dos[2..]
        }
    } else if !dos.is_empty() && is_sep(dos[0]) {
        for &u in cwd.iter().take(3) {
            push(out, u, &mut n);
        }
        &dos[1..]
    } else {
        for &u in cwd {
            push(out, u, &mut n);
        }
        dos
    };
    if n > 0 && out[n - 1] != SLASH {
        push(out, SLASH, &mut n);
    }
    // Components, with "." dropped and ".." going up (not above the root).
    for part in rest.split(|&u| is_sep(u)) {
        if part.is_empty() || part == [b'.' as u16] {
            continue;
        }
        if part == [b'.' as u16, b'.' as u16] {
            if n > 3 {
                n -= 1; // the trailing backslash
                while n > 3 && out[n - 1] != SLASH {
                    n -= 1;
                }
            }
            continue;
        }
        for &u in part {
            push(out, u, &mut n);
        }
        push(out, SLASH, &mut n);
    }
    // No trailing backslash unless the path is a root or ended with one.
    let trailing = rest.last().is_some_and(|&u| is_sep(u)) || n <= 3;
    if !trailing && n > 3 {
        n -= 1;
    }
    let last = out[..n].iter().rposition(|&u| u == SLASH).map_or(0, |i| i + 1);
    Some((n, last))
}

/// RTL_RELATIVE_NAME_U: RelativeName (UNICODE_STRING), ContainingDirectory, CurDirRef.
#[repr(C)]
pub struct RelativeName {
    relative: UnicodeString,
    directory: u64,
    reference: u64,
}

unsafe fn dos_to_nt(dos: *const u16, nt: *mut UnicodeString, part: *mut *mut u16, relative: *mut RelativeName) -> NtStatus {
    if dos.is_null() || nt.is_null() {
        return status::OBJECT_NAME_INVALID;
    }
    let src = unsafe { core::slice::from_raw_parts(dos, wlen(dos)) };
    let mut full = [0u16; 1024];
    let Some((len, last)) = full_dos_path(src, &mut full) else { return status::OBJECT_NAME_INVALID };
    let prefix: [u16; 4] = [SLASH, b'?' as u16, b'?' as u16, SLASH];
    if !unsafe { make(nt, prefix.iter().copied().chain(full[..len].iter().copied())) } {
        return status::NO_MEMORY;
    }
    unsafe {
        if !part.is_null() {
            *part = if last < len { (*nt).buffer.add(4 + last) } else { core::ptr::null_mut() };
        }
        if !relative.is_null() {
            core::ptr::write_bytes(relative as *mut u8, 0, core::mem::size_of::<RelativeName>());
        }
    }
    status::SUCCESS
}

#[no_mangle]
pub unsafe extern "system" fn RtlDosPathNameToNtPathName_U(dos: *const u16, nt: *mut UnicodeString, part: *mut *mut u16, relative: *mut RelativeName) -> u8 {
    (unsafe { dos_to_nt(dos, nt, part, relative) } == status::SUCCESS) as u8
}

#[no_mangle]
pub unsafe extern "system" fn RtlDosPathNameToNtPathName_U_WithStatus(dos: *const u16, nt: *mut UnicodeString, part: *mut *mut u16, relative: *mut RelativeName) -> NtStatus {
    unsafe { dos_to_nt(dos, nt, part, relative) }
}

#[no_mangle]
pub unsafe extern "system" fn RtlDosPathNameToRelativeNtPathName_U(dos: *const u16, nt: *mut UnicodeString, part: *mut *mut u16, relative: *mut RelativeName) -> u8 {
    unsafe { RtlDosPathNameToNtPathName_U(dos, nt, part, relative) }
}

#[no_mangle]
pub unsafe extern "system" fn RtlDosPathNameToRelativeNtPathName_U_WithStatus(dos: *const u16, nt: *mut UnicodeString, part: *mut *mut u16, relative: *mut RelativeName) -> NtStatus {
    unsafe { dos_to_nt(dos, nt, part, relative) }
}

#[no_mangle]
pub extern "system" fn RtlReleaseRelativeName(_relative: *mut RelativeName) {}

/// RtlGetFullPathName_U: the absolute DOS path, in bytes written.
#[no_mangle]
pub unsafe extern "system" fn RtlGetFullPathName_U(dos: *const u16, size: u32, out: *mut u16, part: *mut *mut u16) -> u32 {
    let src = unsafe { core::slice::from_raw_parts(dos, wlen(dos)) };
    let mut full = [0u16; 1024];
    let Some((len, last)) = full_dos_path(src, &mut full) else { return 0 };
    if (len + 1) * 2 > size as usize {
        return ((len + 1) * 2) as u32;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(full.as_ptr(), out, len);
        *out.add(len) = 0;
        if !part.is_null() {
            *part = if last < len { out.add(last) } else { core::ptr::null_mut() };
        }
    }
    (len * 2) as u32
}

// -----| files, tokens, process |-----

type CreateFile = unsafe extern "system" fn(*mut u64, u32, *const u8, *mut u8, *const i64, u32, u32, u32, u32, *const u8, u32) -> NtStatus;

/// NtCreateFile: pipes by name (and the pipe folder) here, everything else
/// in the kernel.
#[no_mangle]
pub unsafe extern "system" fn NtCreateFile(handle: *mut u64, access: u32, attrs: *const u8, iosb: *mut u8, size: *const i64, file_attrs: u32, share: u32, disposition: u32, options: u32, ea: *const u8, ea_len: u32) -> NtStatus {
    if !attrs.is_null() {
        if let Some(s) = unsafe { open_pipe(handle, attrs) } {
            if s == 0 {
                unsafe { apply_inherit(handle, attrs) };
            }
            return s;
        }
    }
    let raw: CreateFile = unsafe { core::mem::transmute(crate::VeilNtCreateFileRaw as *const ()) };
    unsafe { raw(handle, access, attrs, iosb, size, file_attrs, share, disposition, options, ea, ea_len) }
}

#[no_mangle]
pub unsafe extern "system" fn ZwCreateFile(handle: *mut u64, access: u32, attrs: *const u8, iosb: *mut u8, size: *const i64, file_attrs: u32, share: u32, disposition: u32, options: u32, ea: *const u8, ea_len: u32) -> NtStatus {
    unsafe { NtCreateFile(handle, access, attrs, iosb, size, file_attrs, share, disposition, options, ea, ea_len) }
}

/// NtOpenFile: NtCreateFile with FILE_OPEN.
#[no_mangle]
pub unsafe extern "system" fn NtOpenFile(handle: *mut u64, access: u32, attrs: *const u8, iosb: *mut u8, share: u32, options: u32) -> NtStatus {
    // Opening the named-pipe folder, or a nameless pipe through its server.
    if let Some(s) = unsafe { open_pipe(handle, attrs) } {
        if s == 0 {
            unsafe { apply_inherit(handle, attrs) };
        }
        return s;
    }
    let create: CreateFile = unsafe { core::mem::transmute(crate::VeilNtCreateFileRaw as *const ()) };
    unsafe { create(handle, access, attrs, iosb, core::ptr::null(), 0, share, 1, options, core::ptr::null(), 0) }
}

#[no_mangle]
pub unsafe extern "system" fn ZwOpenFile(handle: *mut u64, access: u32, attrs: *const u8, iosb: *mut u8, share: u32, options: u32) -> NtStatus {
    unsafe { NtOpenFile(handle, access, attrs, iosb, share, options) }
}

/// OBJECT_ATTRIBUTES: Length, RootDirectory at 8, ObjectName at 16.
unsafe fn pipe_attrs(attrs: *const u8) -> (u64, &'static [u16]) {
    unsafe {
        let root = core::ptr::read_unaligned(attrs.add(8) as *const u64);
        let name = core::ptr::read_unaligned(attrs.add(16) as *const *const u8);
        if name.is_null() {
            return (root, &[]);
        }
        let len = core::ptr::read_unaligned(name as *const u16) as usize / 2;
        let buf = core::ptr::read_unaligned(name.add(8) as *const *const u16);
        (root, if len == 0 { &[] } else { core::slice::from_raw_parts(buf, len) })
    }
}

fn is_pipe_folder(name: &[u16]) -> bool {
    const FOLDER: &[u8] = b"\\Device\\NamedPipe\\";
    name.len() == FOLDER.len() && name.iter().zip(FOLDER).all(|(&u, &b)| u < 0x80 && (u as u8).eq_ignore_ascii_case(&b))
}

/// Handles this process holds that stand for the pipe folder (an event
/// each): names relative to them are pipes.
static PIPE_FOLDERS: [core::sync::atomic::AtomicU64; 16] = [const { core::sync::atomic::AtomicU64::new(0) }; 16];

fn is_folder_handle(h: u64) -> bool {
    h != 0 && PIPE_FOLDERS.iter().any(|f| f.load(core::sync::atomic::Ordering::Relaxed) == h)
}

/// The kernel's name for a pipe, "\\.\pipe\NAME" and a NUL, if `name` (under
/// `root`) is one: relative to a pipe-folder handle, or under
/// \Device\NamedPipe\ or \??\pipe\.
fn pipe_full_name(root: u64, name: &[u16]) -> Option<[u16; 300]> {
    fn strip<'a>(n: &'a [u16], prefix: &[u8]) -> Option<&'a [u16]> {
        (n.len() > prefix.len() && n.iter().zip(prefix).all(|(&u, &b)| u < 0x80 && (u as u8).eq_ignore_ascii_case(&b))).then(|| &n[prefix.len()..])
    }
    let rest = if is_folder_handle(root) {
        name
    } else if root == 0 {
        strip(name, b"\\Device\\NamedPipe\\").or_else(|| strip(name, b"\\??\\pipe\\"))?
    } else {
        return None;
    };
    if rest.is_empty() || rest.len() > 280 {
        return None;
    }
    let mut out = [0u16; 300];
    let prefix = b"\\\\.\\pipe\\";
    for (o, &b) in out.iter_mut().zip(prefix) {
        *o = b as u16;
    }
    out[prefix.len()..prefix.len() + rest.len()].copy_from_slice(rest);
    Some(out)
}

fn veil_pipe() -> unsafe extern "system" fn(u64, u64, u64, u64) -> NtStatus {
    unsafe { core::mem::transmute(crate::VeilPipe as *const ()) }
}

/// A pipe end goes to children only with OBJ_INHERIT: a child holding the write
/// end of its own stdin would never see the end of it.
unsafe fn apply_inherit(handle: *mut u64, attrs: *const u8) {
    // OBJECT_ATTRIBUTES.Attributes, after the length, root and name.
    let inherit = !attrs.is_null() && unsafe { *(attrs.add(24) as *const u32) } & 2 != 0;
    let info = [inherit as u8, 0];
    type SetObject = unsafe extern "system" fn(u64, u32, *const u8, u32) -> NtStatus;
    let set: SetObject = unsafe { core::mem::transmute(crate::NtSetInformationObject as *const ()) };
    unsafe { set(*handle, 4, info.as_ptr(), 2) };
}

unsafe fn open_pipe(handle: *mut u64, attrs: *const u8) -> Option<NtStatus> {
    let (root, name) = unsafe { pipe_attrs(attrs) };
    const NULL_DEVICE: &[u8] = b"\\Device\\Null";
    if root == 0 && name.len() == NULL_DEVICE.len() && name.iter().zip(NULL_DEVICE).all(|(&u, &b)| u < 0x80 && (u as u8).eq_ignore_ascii_case(&b)) {
        return Some(unsafe { veil_pipe()(7, handle as u64, 0, 0) });
    }
    if is_pipe_folder(name) {
        // Nothing to open: an event stands for the folder.
        type CreateEvent = unsafe extern "system" fn(*mut u64, u32, *const u8, u32, u8) -> NtStatus;
        let create: CreateEvent = unsafe { core::mem::transmute(crate::NtCreateEvent as *const ()) };
        let s = unsafe { create(handle, 0x1F0003, core::ptr::null(), 0, 0) };
        if s == 0 {
            let h = unsafe { *handle };
            if let Some(slot) = PIPE_FOLDERS.iter().find(|f| f.load(core::sync::atomic::Ordering::Relaxed) == 0) {
                slot.store(h, core::sync::atomic::Ordering::Relaxed);
            }
        }
        return Some(s);
    }
    // A named pipe's client end.
    if let Some(full) = pipe_full_name(root, name) {
        return Some(unsafe { veil_pipe()(1, full.as_ptr() as u64, handle as u64, 0) });
    }
    if root != 0 && name.is_empty() {
        let s = unsafe { veil_pipe()(6, root, handle as u64, 0) };
        // INVALID_HANDLE: the root wasn't a pipe, so it's an ordinary open.
        if s != nt_abi::status::INVALID_HANDLE {
            return Some(s);
        }
    }
    None
}

/// A nameless pipe, reached through this handle (NtOpenFile with it as root),
/// as Rust's standard library makes its pipes. Names under the folder aren't
/// offered here: CreateNamedPipe is how those are made.
#[no_mangle]
pub unsafe extern "system" fn NtCreateNamedPipeFile(handle: *mut u64, _access: u32, attrs: *const u8, iosb: *mut u64, _share: u32, _disposition: u32, _options: u32, _pipe_type: u32, _read_mode: u32, _completion: u32, _max: u32, inbound: u32, outbound: u32, _timeout: *const i64) -> NtStatus {
    // Named (under the pipe folder, as the MSYS2 runtime makes its pipes) or
    // nameless.
    let (root, name) = if attrs.is_null() { (0, &[][..]) } else { unsafe { pipe_attrs(attrs) } };
    let full = pipe_full_name(root, name);
    let name_ptr = full.as_ref().map_or(0, |f| f.as_ptr() as u64);
    let s = unsafe { veil_pipe()(0, name_ptr, handle as u64, inbound.max(outbound) as u64) };
    if s == 0 {
        unsafe { apply_inherit(handle, attrs) };
    }
    if s == 0 && !iosb.is_null() {
        unsafe {
            *iosb = 0;
            *iosb.add(1) = 2; // FILE_CREATED
        }
    }
    s
}

/// The status behind the last error: not kept, so nothing to report.
#[no_mangle]
pub extern "system" fn RtlGetLastNtStatus() -> NtStatus {
    0
}

const STATUS_NO_TOKEN: NtStatus = 0xC000_007Cu32 as i32;
const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC000_0010u32 as i32;
const STATUS_NOT_FOUND: NtStatus = 0xC000_0225u32 as i32;

/// Threads don't impersonate, so they have no token.
#[no_mangle]
pub extern "system" fn NtOpenThreadToken(_thread: u64, _access: u32, _as_self: u8, token: *mut u64) -> NtStatus {
    if !token.is_null() {
        unsafe { *token = 0 };
    }
    STATUS_NO_TOKEN
}

#[no_mangle]
pub extern "system" fn NtOpenThreadTokenEx(thread: u64, access: u32, as_self: u8, _attrs: u32, token: *mut u64) -> NtStatus {
    NtOpenThreadToken(thread, access, as_self, token)
}

// -----| the token: one user, the same everywhere |-----
//
// The process token is a pseudo handle (-5), as kernel32's OpenProcessToken
// gives; every token call answers for the one user, S-1-5-21-1000-1000-1000-1001,
// whose primary group is ...-513, at medium integrity.

const TOKEN: u64 = (-5i64) as u64;
const STATUS_BUFFER_TOO_SMALL_: NtStatus = 0xC000_0023u32 as i32;

const USER_SID: [u8; 28] = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xE8, 3, 0, 0, 0xE8, 3, 0, 0, 0xE8, 3, 0, 0, 0xE9, 3, 0, 0];
const GROUP_SID: [u8; 28] = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xE8, 3, 0, 0, 0xE8, 3, 0, 0, 0xE8, 3, 0, 0, 0x01, 2, 0, 0];
const EVERYONE_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const USERS_SID: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 2, 0, 0];
const AUTH_USERS_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
const MEDIUM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0];

#[no_mangle]
pub extern "system" fn NtOpenProcessToken(_process: u64, _access: u32, token: *mut u64) -> NtStatus {
    if token.is_null() {
        return status::ACCESS_VIOLATION;
    }
    unsafe { *token = TOKEN };
    status::SUCCESS
}

#[no_mangle]
pub extern "system" fn NtOpenProcessTokenEx(process: u64, access: u32, _attrs: u32, token: *mut u64) -> NtStatus {
    NtOpenProcessToken(process, access, token)
}

/// A token answer: fixed part, then SIDs it points at (offsets from the
/// start become pointers once it's in the caller's buffer).
struct Answer {
    buf: [u8; 256],
    len: usize,
    /// Where a pointer goes, and the offset it points at.
    ptrs: [(usize, usize); 8],
    n_ptrs: usize,
}

impl Answer {
    fn new(fixed: usize) -> Self {
        Self { buf: [0; 256], len: fixed, ptrs: [(0, 0); 8], n_ptrs: 0 }
    }
    fn u32_at(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    /// Append a SID; the pointer at `ptr_at` will point at it.
    fn sid(&mut self, ptr_at: usize, sid: &[u8]) {
        let at = self.len.next_multiple_of(4);
        self.buf[at..at + sid.len()].copy_from_slice(sid);
        self.len = at + sid.len();
        self.ptrs[self.n_ptrs] = (ptr_at, at);
        self.n_ptrs += 1;
    }
}

#[no_mangle]
pub unsafe extern "system" fn NtQueryInformationToken(token: u64, class: u32, info: *mut u8, len: u32, ret: *mut u32) -> NtStatus {
    if token != TOKEN {
        return status::INVALID_HANDLE;
    }
    let a = match class {
        // TokenUser, TokenIntegrityLevel: a SID_AND_ATTRIBUTES.
        1 | 25 => {
            let mut a = Answer::new(16);
            if class == 25 {
                a.u32_at(8, 0x20); // SE_GROUP_INTEGRITY
                a.sid(0, &MEDIUM_SID);
            } else {
                a.sid(0, &USER_SID);
            }
            a
        }
        // TokenGroups: the primary group, Everyone, Users, Authenticated Users.
        2 => {
            let groups: [&[u8]; 4] = [&GROUP_SID, &EVERYONE_SID, &USERS_SID, &AUTH_USERS_SID];
            let mut a = Answer::new(8 + 16 * groups.len());
            a.u32_at(0, groups.len() as u32);
            for (i, g) in groups.iter().enumerate() {
                a.u32_at(8 + 16 * i + 8, 7); // mandatory, enabled by default, enabled
                a.sid(8 + 16 * i, g);
            }
            a
        }
        // TokenPrivileges: none listed.
        3 => Answer::new(4),
        // TokenOwner, TokenPrimaryGroup: a pointer to a SID.
        4 | 5 => {
            let mut a = Answer::new(8);
            a.sid(0, if class == 4 { &USER_SID } else { &GROUP_SID });
            a
        }
        // TokenDefaultDacl: none (a NULL ACL pointer).
        6 => Answer::new(8),
        // TokenSource: "User32  " and a LUID.
        7 => {
            let mut a = Answer::new(16);
            a.buf[..8].copy_from_slice(b"User32  ");
            a
        }
        // TokenType: primary.
        8 => {
            let mut a = Answer::new(4);
            a.u32_at(0, 1);
            a
        }
        // TokenStatistics: ids, type primary, the group count.
        10 => {
            let mut a = Answer::new(56);
            a.u32_at(0, 0x1000);
            a.u32_at(8, 0x3E7);
            a.buf[16..24].copy_from_slice(&i64::MAX.to_le_bytes());
            a.u32_at(24, 1);
            a.u32_at(40, 4);
            a
        }
        // TokenSessionId: 1.
        12 => {
            let mut a = Answer::new(4);
            a.u32_at(0, 1);
            a
        }
        // TokenElevationType: default.
        18 => {
            let mut a = Answer::new(4);
            a.u32_at(0, 1);
            a
        }
        // TokenElevation: not elevated; TokenIsAppContainer: no.
        20 | 29 => Answer::new(4),
        _ => return status::INVALID_INFO_CLASS,
    };
    unsafe {
        if !ret.is_null() {
            *ret = a.len as u32;
        }
        if (len as usize) < a.len || info.is_null() {
            return STATUS_BUFFER_TOO_SMALL_;
        }
        core::ptr::copy_nonoverlapping(a.buf.as_ptr(), info, a.len);
        for &(at, target) in &a.ptrs[..a.n_ptrs] {
            core::ptr::write_unaligned(info.add(at) as *mut u64, info.add(target) as u64);
        }
    }
    status::SUCCESS
}

/// Process settings (priority, error mode, ...) are accepted.
#[no_mangle]
pub extern "system" fn NtSetInformationProcess(_process: u64, _class: u32, _info: *const u8, _len: u32) -> NtStatus {
    status::SUCCESS
}

#[no_mangle]
pub extern "system" fn NtFsControlFile(_h: u64, _ev: u64, _apc: usize, _ctx: usize, _iosb: *mut u8, _code: u32, _in: usize, _in_len: u32, _out: usize, _out_len: u32) -> NtStatus {
    STATUS_INVALID_DEVICE_REQUEST
}

#[no_mangle]
pub extern "system" fn NtCancelSynchronousIoFile(_thread: u64, _request: *mut u8, _iosb: *mut u8) -> NtStatus {
    STATUS_NOT_FOUND
}

// -----| what Bun-built programs (claude.exe) reach for |-----

const STATUS_INFO_LENGTH_MISMATCH: NtStatus = 0xC000_0004u32 as i32;

fn peb_u32(offset: u64) -> u32 {
    let peb: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, readonly));
        read_unaligned((peb + offset) as *const u32)
    }
}

/// The address a syscall stub (crate root) is at, as a typed function.
macro_rules! stub {
    ($name:ident : $ty:ty) => {
        unsafe { core::mem::transmute::<*const (), $ty>(crate::$name as *const ()) }
    };
}

/// NtQuerySystemInformation: basic information (0) and per-processor times
/// (8, all zero: no accounting yet). Other classes aren't kept.
#[no_mangle]
pub unsafe extern "system" fn NtQuerySystemInformation(class: u32, info: *mut u8, length: u32, ret: *mut u32) -> NtStatus {
    let cpus = peb_u32(0xB8).max(1);
    let need = match class {
        0 => 64,
        8 => 48 * cpus,
        _ => return status::INVALID_INFO_CLASS,
    };
    if !ret.is_null() {
        unsafe { *ret = need };
    }
    if length < need || info.is_null() {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    unsafe { core::ptr::write_bytes(info, 0, need as usize) };
    if class == 0 {
        let mut mem = [0u64; 2];
        let sysinfo = stub!(VeilSysInfo: unsafe extern "system" fn(u64, *mut u64, u64) -> NtStatus);
        unsafe { sysinfo(1, mem.as_mut_ptr(), 16) };
        let w32 = |o: usize, v: u32| unsafe { core::ptr::write_unaligned(info.add(o) as *mut u32, v) };
        let w64 = |o: usize, v: u64| unsafe { core::ptr::write_unaligned(info.add(o) as *mut u64, v) };
        w32(4, 156_250); // TimerResolution (100 ns units): 15.625 ms
        w32(8, 4096);
        w32(12, (mem[0] / 4096) as u32);
        w32(16, 1);
        w32(20, (mem[0] / 4096) as u32);
        w32(24, 0x1_0000);
        w64(32, 0x1_0000);
        w64(40, 0x7FFF_FFFE_FFFF);
        w64(48, if cpus >= 64 { u64::MAX } else { (1u64 << cpus) - 1 });
        unsafe { *info.add(56) = cpus as u8 };
    }
    status::SUCCESS
}

/// RtlWaitOnAddress(address, compare, size, timeout*): timeout in 100 ns
/// units, negative for relative (the only kind kept), null for forever.
#[no_mangle]
pub unsafe extern "system" fn RtlWaitOnAddress(addr: *const u8, compare: *const u8, size: usize, timeout: *const i64) -> NtStatus {
    let ms = if timeout.is_null() {
        u64::MAX
    } else {
        let t = unsafe { read_unaligned(timeout) };
        if t < 0 { (-t) as u64 / 10_000 } else { 0 }
    };
    let wait = stub!(VeilWaitAddress: unsafe extern "system" fn(u64, u64, u64, u64) -> NtStatus);
    unsafe { wait(addr as u64, compare as u64, size as u64, ms) }
}

#[no_mangle]
pub unsafe extern "system" fn RtlWakeAddressAll(addr: *const u8) {
    let wake = stub!(VeilWakeAddress: unsafe extern "system" fn(u64) -> NtStatus);
    unsafe { wake(addr as u64) };
}

#[no_mangle]
pub unsafe extern "system" fn RtlWakeAddressSingle(addr: *const u8) {
    let wake = stub!(VeilWakeAddress: unsafe extern "system" fn(u64) -> NtStatus);
    unsafe { wake(addr as u64) };
}

/// RtlExitUserProcess: the process ends with `code` (no DLL detach yet).
#[no_mangle]
pub unsafe extern "system" fn RtlExitUserProcess(code: u32) -> ! {
    loop {
        unsafe {
            core::arch::asm!("syscall", in("r10") u64::MAX, in("rdx") code as u64,
                inlateout("rax") nt_abi::sys::NT_TERMINATE_PROCESS as u64 => _, lateout("rcx") _, lateout("r11") _)
        };
    }
}

/// RtlFillMemory(destination, length, fill): note the order.
#[no_mangle]
pub unsafe extern "system" fn RtlFillMemory(dst: *mut u8, length: usize, fill: u8) {
    unsafe { core::ptr::write_bytes(dst, fill, length) };
}

/// VerSetConditionMask: three bits of condition for each VER_* type bit.
#[no_mangle]
pub extern "system" fn VerSetConditionMask(mask: u64, type_mask: u32, condition: u8) -> u64 {
    let mut m = mask;
    for i in 0..8 {
        if type_mask & (1 << i) != 0 {
            m |= ((condition & 7) as u64) << (i * 3);
        }
    }
    m
}

/// RtlAddGrowableFunctionTable: JIT code's unwind data. Kept nowhere yet
/// (exceptions don't unwind through JIT frames), so accepted and dropped.
#[no_mangle]
pub unsafe extern "system" fn RtlAddGrowableFunctionTable(table: *mut u64, _entries: *const u8, _count: u32, _max: u32, _base: u64, _end: u64) -> NtStatus {
    if !table.is_null() {
        unsafe { *table = 1 };
    }
    status::SUCCESS
}

#[no_mangle]
pub extern "system" fn RtlGrowFunctionTable(_table: u64, _count: u32) {}

#[no_mangle]
pub extern "system" fn RtlDeleteGrowableFunctionTable(_table: u64) {}

/// Security descriptors aren't kept.

#[no_mangle]
pub extern "system" fn NtQuerySecurityObject(_h: u64, _info: u32, _sd: *mut u8, _length: u32, _ret: *mut u32) -> NtStatus {
    status::NOT_IMPLEMENTED
}

#[no_mangle]
pub extern "system" fn NtSetSecurityObject(_h: u64, _info: u32, _sd: *const u8) -> NtStatus {
    status::SUCCESS // accepted; nothing enforces security descriptors
}

#[no_mangle]
pub unsafe extern "system" fn RtlCompareMemory(
    source1: *const u8,
    source2: *const u8,
    length: usize,
) -> usize {
    let mut matched = 0;

    while matched < length {
        let a = unsafe { source1.add(matched).read_volatile() };
        let b = unsafe { source2.add(matched).read_volatile() };

        if a != b {
            break;
        }

        matched += 1;
    }

    matched
}

fn current_teb() -> *mut u8 {
    let teb: *mut u8;

    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, readonly, preserves_flags)
        );
    }

    teb
}

#[no_mangle]
pub extern "system" fn RtlGetLastWin32Error() -> u32 {
    unsafe {
        *(current_teb().add(nt_abi::layout::TEB_LAST_ERROR)
            as *const u32)
    }
}

#[no_mangle]
pub extern "system" fn RtlSetLastWin32Error(error: u32) {
    unsafe {
        *(current_teb().add(nt_abi::layout::TEB_LAST_ERROR)
            as *mut u32) = error;
    }
}

#[no_mangle]
pub unsafe extern "system" fn RtlQueryPerformanceCounter(
    counter: *mut i64,
) -> i32 {
    if counter.is_null() {
        return 0;
    }

    unsafe {
        *counter = core::arch::x86_64::_rdtsc() as i64;
    }

    1
}
