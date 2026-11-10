// =============================================================================
// VEILOS: per-process module loader (WIN32_DESIGN.md, step W1)
// =============================================================================
//
// Maps a Windows program's EXE and every DLL it needs into the process's own
// address space and links them:
//
//   * DLLs are found in /SYSTEM, then in the EXE's folder, loaded once per
//     process, and their own imports resolved in turn (depth first, so cycles
//     terminate: a module is registered before its imports are bound).
//   * Imports bind by name or ordinal, to code or data exports, following
//     forwarders ("w1dep.dep_mul", "NTDLL.RtlAllocateHeap").
//   * API-set names (api-ms-win-core-*, api-ms-win-crt-*) map to the DLL that
//     implements them (`api_set_host`).
//   * A name no DLL on disk exports falls back to the kernel's built-in Win32
//     functions (`dll::DLL_REGISTRY`): a `mov r10,rcx; mov eax,ID; syscall;
//     ret` thunk. Anything else gets its own stub, which returns 0 and logs
//     the name the first time it's called; the stub is writable, so a data
//     import nothing provides can still be written.
//   * Static TLS: each module with a TLS directory gets an index and a block
//     for the main thread (TEB.ThreadLocalStoragePointer).
//   * Startup: a generated routine at INIT_ENTRY calls every module's TLS
//     callbacks and DllMain(DLL_PROCESS_ATTACH), dependencies first, then
//     the EXE's entry point; if that returns, ExitProcess(its value), as
//     Windows' BaseThreadInitThunk does.
//   * PEB.Ldr lists the modules (load, memory and initialisation order).
//   * Sections get their own protection (read-only / writable, NX unless
//     executable) once linking is done.
//   * The Linker stays with the process (Process::linker) for LoadLibrary
//     and GetProcAddress later (`load_at_runtime`, `proc_address`). A DLL
//     that exists only as kernel built-ins gets a pseudo module handle.
//
// Regions (per process, so fixed addresses don't collide between processes):

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use x86_64::structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

use crate::executable::PeFile;
use crate::memory;
use alloc::sync::Arc;
use crate::nt_demand::Sec;
use crate::nt_file::SharedFile;

/// DLL images, bump-allocated, 64 KiB aligned.
const DLL_REGION: u64 = 0x2_0000_0000;
/// The startup routine (TLS callbacks, DllMains, then the EXE entry point).
pub const INIT_ENTRY: u64 = 0x3_0000_0000;
const INIT_REGION_SIZE: u64 = 0x1_0000;
/// Syscall thunks for built-in functions (read-execute once linked).
const THUNK_REGION: u64 = INIT_ENTRY + INIT_REGION_SIZE;
/// One 32-byte slot per unresolved import (writable: data imports land here).
const UNRESOLVED_REGION: u64 = 0x5_0000_0000;
/// LDR entries, strings, TLS blocks and the TLS pointer array (read-write, NX).
const LOADER_DATA_REGION: u64 = 0x6_0000_0000;
/// Pseudo module handles for DLLs that exist only as kernel built-ins
/// (never mapped: GetProcAddress recognises them).
const BUILTIN_HANDLE_BASE: u64 = 0x4_0000_0000;

/// Syscall IDs `UNRESOLVED_SYSCALL_BASE + n` mean "unresolved import n was
/// called" (`subsystem::WindowsSubsystem`).
pub const UNRESOLVED_SYSCALL_BASE: u64 = 0x0100_0000;

/// Forwarder chains longer than this are treated as broken.
const MAX_FORWARD_DEPTH: u32 = 16;

const SCN_CNT_CODE: u32 = 0x0000_0020;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

const DIR_TLS: usize = 9;
const DLL_PROCESS_ATTACH: u64 = 1;

/// The page-table borrows every mapping goes through, plus the list of pages
/// mapped so far (rolled back by the loader if anything fails).
pub struct Mem<'a, M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>> {
    pub mapper: &'a mut M,
    pub fa: &'a mut F,
    pub pages: &'a mut Vec<u64>,
}

impl<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>> Mem<'_, M, F> {
    /// Map `count` zeroed pages at `va`.
    fn map_zeroed(&mut self, va: u64, count: u64, flags: PageTableFlags) -> Result<(), &'static str> {
        for i in 0..count {
            let addr = va + i * 4096;
            let frame = memory::allocate_frame().ok_or("out of memory mapping an image")?;
            memory::map_page_checked(Page::containing_address(VirtAddr::new(addr)), frame, flags, self.mapper, self.fa)?;
            self.pages.push(addr);
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096) };
        }
        Ok(())
    }

    fn protect(&mut self, va: u64, flags: PageTableFlags) {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
        unsafe {
            let _ = self.mapper.update_flags(page, flags).map(|f| f.flush());
        }
    }
}

const RW: PageTableFlags = PageTableFlags::PRESENT.union(PageTableFlags::WRITABLE).union(PageTableFlags::USER_ACCESSIBLE);

/// A region handed out from the bottom, mapping pages as it grows.
struct Bump {
    next: u64,
    mapped_end: u64,
    limit: u64,
}

impl Bump {
    const fn new(start: u64, limit: u64) -> Self {
        Bump { next: start, mapped_end: start, limit }
    }

    fn alloc<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, size: u64, align: u64) -> Result<u64, &'static str> {
        let addr = (self.next + align - 1) & !(align - 1);
        let end = addr + size;
        if end > self.limit {
            return Err("loader region full");
        }
        if end > self.mapped_end {
            let pages = (end - self.mapped_end).div_ceil(4096);
            mem.map_zeroed(self.mapped_end, pages, RW)?;
            self.mapped_end += pages * 4096;
        }
        self.next = end;
        Ok(addr)
    }

    fn used(&self, start: u64) -> (u64, usize) {
        (start, (self.mapped_end - start) as usize)
    }
}

/// What an import of a symbol asks for.
#[derive(Clone, Copy)]
enum Sym<'s> {
    Name(&'s str),
    Ordinal(u16),
}

impl Sym<'_> {
    fn describe(&self) -> String {
        match self {
            Sym::Name(n) => String::from(*n),
            Sym::Ordinal(o) => format!("#{}", o),
        }
    }
}

/// Where a DLL name's symbols come from.
struct Provider {
    /// A loaded module (index into `Linker::modules`).
    real: Option<usize>,
    /// Built-in DLL names to try, in order (the requested name, then its host).
    builtin: Vec<String>,
    /// The name as imported, for log lines.
    label: String,
}

struct Module {
    /// Lower-case file name ("w1lib.dll").
    name: String,
    /// Where it was loaded from ("/SYSTEM/w1lib.dll").
    path: String,
    base: u64,
    size: u64,
    /// DllMain or the EXE entry point (absolute), 0 if none.
    entry: u64,
    is_exe: bool,
    pe: PeFile,
    deps: Vec<usize>,
    tls_index: Option<u32>,
    tls_callbacks: Vec<u64>,
}

/// Built-in function names that must run in user mode (they call back into
/// the program), mapped to the addresses the loader built for them.
pub struct UserModeOverrides {
    pub initterm: u64,
    pub initterm_e: u64,
}

pub struct Linker {
    modules: Vec<Module>,
    exe_dir: String,
    dll_next: u64,
    /// Ranges the process already uses besides modules (its VAD, for loads
    /// at run time): a DLL's preferred base must be clear of them too.
    pub taken: Vec<(u64, u64)>,
    init: Bump,
    thunks: Bump,
    unresolved_slots: Bump,
    data: Bump,
    thunk_by_id: BTreeMap<u32, u64>,
    unresolved_by_name: BTreeMap<String, u64>,
    /// "dll!name" for each unresolved stub, by index.
    pub unresolved: Vec<String>,
    tls_count: u32,
    overrides: UserModeOverrides,
    stats: Stats,
    /// PEB.Ldr, and the modules initialised so far, in order.
    ldr: u64,
    initialized: Vec<usize>,
    /// Pseudo handles handed out for built-in-only DLLs.
    builtin_handles: Vec<String>,
}

#[derive(Default)]
struct Stats {
    to_modules: usize,
    to_builtin: usize,
    unresolved: usize,
}

/// The DLL that implements an API-set contract, if `name` is one. VEILOS's
/// own DLLs host the contracts real Windows puts in kernelbase/ucrtbase;
/// kernel32 also hosts those of shlwapi, shcore and combase (COM, WinRT)
/// until those DLLs exist.
pub fn api_set_host(name: &str) -> Option<&'static str> {
    let n = name;
    if !(n.starts_with("api-ms-win-") || n.starts_with("ext-ms-win-")) {
        return None;
    }
    Some(if n.starts_with("api-ms-win-crt-") {
        "ucrtbase.dll"
    } else if n.starts_with("api-ms-win-core-rtlsupport-") {
        "ntdll.dll"
    } else if n.starts_with("ext-ms-win-") {
        return None;
    } else {
        "kernel32.dll"
    })
}

/// The name behind an API-set ordinal: some contracts export functions by
/// ordinal only, and the host DLL's ordinals are its own.
fn api_set_ordinal(dll: &str, ordinal: u16) -> Option<&'static str> {
    let n = dll.to_ascii_lowercase();
    match ordinal {
        170 if n.starts_with("api-ms-win-shcore-path-l1-1-") => Some("PathIsNetworkPathW"),
        _ => None,
    }
}

/// Whether a module's ordinals are Windows' own: a program's own DLLs, and
/// those of ours numbered to match (comctl32, ws2_32, wsock32, oleaut32).
fn ordinals_are_windows(m: &Module) -> bool {
    !m.path.to_ascii_lowercase().starts_with("/system/")
        || matches!(m.name.as_str(), "comctl32.dll" | "ws2_32.dll" | "wsock32.dll" | "oleaut32.dll")
}

/// Lower-case, with ".dll" added when there's no extension.
fn normalize(name: &str) -> String {
    let mut n = name.to_ascii_lowercase();
    if !n.contains('.') {
        n.push_str(".dll");
    }
    n
}

/// The first bytes of an image, exactly up to the end of its headers: parsing
/// them gives sections and directories, and nothing that needs the rest.
pub fn read_headers(file: &SharedFile) -> Result<Vec<u8>, &'static str> {
    let mut first = alloc::vec![0u8; 4096];
    let n = file.read_at(0, &mut first).map_err(|_| "can't read the image")?;
    first.truncate(n);
    let pe = first.get(0x3C..0x40).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or("image too small")? as usize;
    let at = pe + 24 + 60;
    let size = first.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or("truncated PE header")? as usize;
    if size > 1 << 20 {
        return Err("PE headers too large");
    }
    let mut headers = alloc::vec![0u8; size];
    let n = file.read_at(0, &mut headers).map_err(|_| "can't read the image")?;
    headers.truncate(n);
    Ok(headers)
}

/// IMAGE_IMPORT_DESCRIPTORs of the image at `base`.
fn read_imports(base: u64, dir: u32) -> Vec<crate::executable::ImportedDll> {
    let mut out = Vec::new();
    if dir == 0 {
        return out;
    }
    let mut at = base + dir as u64;
    loop {
        let (oft, name, ft) = (read_u32(at), read_u32(at + 12), read_u32(at + 16));
        if name == 0 && ft == 0 {
            return out;
        }
        out.push(crate::executable::ImportedDll { name: read_cstr(base + name as u64), original_first_thunk: oft, first_thunk: ft });
        at += 20;
    }
}

/// An export's RVA by name: export names are sorted, so a binary search touches
/// only a few pages of even a very large table.
fn export_by_name(base: u64, dir: u32, name: &str) -> Option<u32> {
    if dir == 0 {
        return None;
    }
    let d = base + dir as u64;
    let (functions, names, ordinals) = (read_u32(d + 28), read_u32(d + 32), read_u32(d + 36));
    let (mut lo, mut hi) = (0u64, read_u32(d + 24) as u64);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let candidate = read_cstr(base + read_u32(base + names as u64 + mid * 4) as u64);
        match candidate.as_str().cmp(name) {
            core::cmp::Ordering::Equal => {
                let ord = unsafe { core::ptr::read_unaligned((base + ordinals as u64 + mid * 2) as *const u16) } as u64;
                return Some(read_u32(base + functions as u64 + ord * 4));
            }
            core::cmp::Ordering::Less => lo = mid + 1,
            core::cmp::Ordering::Greater => hi = mid,
        }
    }
    None
}

fn export_by_ordinal(base: u64, dir: u32, ordinal: u16) -> Option<u32> {
    if dir == 0 {
        return None;
    }
    let d = base + dir as u64;
    let (ord_base, count, functions) = (read_u32(d + 16), read_u32(d + 20), read_u32(d + 28));
    let i = (ordinal as u32).checked_sub(ord_base)?;
    if i >= count {
        return None;
    }
    Some(read_u32(base + functions as u64 + i as u64 * 4)).filter(|&rva| rva != 0)
}

fn read_u32(addr: u64) -> u32 {
    unsafe { core::ptr::read_unaligned(addr as *const u32) }
}
fn read_u64(addr: u64) -> u64 {
    unsafe { core::ptr::read_unaligned(addr as *const u64) }
}
fn write_u64(addr: u64, v: u64) {
    unsafe { core::ptr::write_unaligned(addr as *mut u64, v) }
}

/// A NUL-terminated ASCII string in mapped memory (at most 512 bytes).
fn read_cstr(addr: u64) -> String {
    let mut s = String::new();
    for i in 0..512 {
        let b = unsafe { *((addr + i) as *const u8) };
        if b == 0 {
            break;
        }
        s.push(b as char);
    }
    s
}

/// Offset of the optional header in a mapped or file image.
fn opt_header(image: u64) -> u64 {
    image + read_u32(image + 0x3C) as u64 + 24
}

/// (rva, size) of data directory `index` of a mapped image.
fn data_dir(base: u64, index: usize) -> (u32, u32) {
    let d = opt_header(base) + 112 + index as u64 * 8;
    (read_u32(d), read_u32(d + 4))
}

impl Linker {
    pub fn new(exe_path: &str) -> Self {
        let exe_dir = match exe_path.rfind('/') {
            Some(0) | None => String::from("/"),
            Some(i) => String::from(&exe_path[..i]),
        };
        Linker {
            modules: Vec::new(),
            exe_dir,
            dll_next: DLL_REGION,
            taken: Vec::new(),
            init: Bump::new(INIT_ENTRY, INIT_ENTRY + INIT_REGION_SIZE),
            thunks: Bump::new(THUNK_REGION, UNRESOLVED_REGION),
            unresolved_slots: Bump::new(UNRESOLVED_REGION, LOADER_DATA_REGION),
            data: Bump::new(LOADER_DATA_REGION, LOADER_DATA_REGION + 0x1000_0000),
            thunk_by_id: BTreeMap::new(),
            unresolved_by_name: BTreeMap::new(),
            unresolved: Vec::new(),
            tls_count: 0,
            overrides: UserModeOverrides { initterm: 0, initterm_e: 0 },
            stats: Stats::default(),
            ldr: 0,
            initialized: Vec::new(),
            builtin_handles: Vec::new(),
        }
    }

    /// Set the user-mode `_initterm`/`_initterm_e` (built with the TEB, after
    /// the EXE is mapped).
    pub fn set_user_mode_overrides(&mut self, o: UserModeOverrides) {
        self.overrides = o;
    }

    /// Map an image's headers and sections at `base` (writable for now) and
    /// apply its relocations. Returns SizeOfImage.
    fn map_image(file: &Arc<SharedFile>, headers: &[u8], pe: &mut PeFile, base: u64) -> Result<u64, &'static str> {
        let opt = u32::from_le_bytes(headers.get(0x3C..0x40).ok_or("image too small")?.try_into().unwrap()) as usize + 24;
        let field = |at: usize| headers.get(opt + at..opt + at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or("truncated PE header");
        let size_of_image = field(56)? as u64;
        let size_of_headers = field(60)?;
        let sections = pe.sections.iter().map(|s| Sec {
            va: s.virtual_address,
            vsize: s.virtual_size,
            raw_ptr: s.pointer_to_raw_data,
            raw_size: s.size_of_raw_data,
            chars: s.characteristics,
        }).collect();
        // Only pages that get touched are read from the file (nt_demand.rs).
        crate::nt_demand::add_image(base, size_of_image, file.clone(), size_of_headers, sections, base.wrapping_sub(pe.image_base), pe.reloc_dir);
        // The import table is in the image; reading it brings in those pages.
        pe.imports = read_imports(base, pe.import_dir);
        Ok(size_of_image)
    }

    /// Map the EXE. Low preferred bases are moved up out of the kernel's
    /// shared low 4 GiB.
    pub fn load_exe(&mut self, path: &str, file: &Arc<SharedFile>, headers: &[u8], mut pe: PeFile) -> Result<u64, &'static str> {
        let mut base = pe.image_base;
        if base < 0x1_0000_0000 {
            base |= 0x1_0000_0000;
            crate::serial_println!("[MODULES] low image base {:#x} moved to {:#x}", pe.image_base, base);
        }
        let size = Self::map_image(file, headers, &mut pe, base)?;
        let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        let entry = if pe.entry_point != 0 { base + pe.entry_point } else { 0 };
        self.push_module(name, String::from(path), base, size, entry, true, pe);
        Ok(base)
    }

    /// The program's own file name ("w1test.exe").
    pub fn exe_name(&self) -> Option<String> {
        self.modules.iter().find(|m| m.is_exe).map(|m| m.name.clone())
    }

    fn push_module(&mut self, name: String, path: String, base: u64, size: u64, entry: u64, is_exe: bool, pe: PeFile) -> usize {
        crate::serial_println!("[MODULES] {} at {:#x} ({} KiB)", name, base, size / 1024);
        self.modules.push(Module { name, path, base, size, entry, is_exe, pe, deps: Vec::new(), tls_index: None, tls_callbacks: Vec::new() });
        self.modules.len() - 1
    }

    /// The DLL file for `name`: /SYSTEM first, then the EXE's folder.
    fn find_dll_file(&self, name: &str) -> Option<(String, Arc<SharedFile>, Vec<u8>)> {
        let dirs = ["/SYSTEM", self.exe_dir.as_str()];
        for dir in dirs {
            let path = if dir.ends_with('/') { format!("{}{}", dir, name) } else { format!("{}/{}", dir, name) };
            if let Ok(file) = crate::nt_file::open_mapped(&path) {
                if let Ok(headers) = read_headers(&file) {
                    return Some((path, file, headers));
                }
            }
        }
        None
    }

    /// Load the DLL `name` (already normalised) if it exists on disk.
    fn load_dll<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, name: &str) -> Result<Option<usize>, &'static str> {
        if let Some(i) = self.modules.iter().position(|m| m.name == name) {
            return Ok(Some(i));
        }
        let Some((path, file, data)) = self.find_dll_file(name) else { return Ok(None) };
        self.load_found(mem, name, path, file, data)
    }

    /// Load the DLL at exactly `path`, as LoadLibrary does when given a full
    /// path. A system DLL already loaded stays the only copy of itself.
    fn load_dll_at<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, path: &str, name: &str) -> Result<Option<usize>, &'static str> {
        let loaded = |m: &Module| {
            m.path.eq_ignore_ascii_case(path) || (m.name == name && m.path.to_ascii_uppercase().starts_with("/SYSTEM/"))
        };
        if let Some(i) = self.modules.iter().position(loaded) {
            return Ok(Some(i));
        }
        let Ok(file) = crate::nt_file::open_mapped(path) else { return Ok(None) };
        let Ok(data) = read_headers(&file) else { return Ok(None) };
        self.load_found(mem, name, String::from(path), file, data)
    }

    /// Map the DLL file that was found, and bind what it imports.
    fn load_found<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, name: &str, path: String, file: Arc<SharedFile>, data: Vec<u8>) -> Result<Option<usize>, &'static str> {
        let mut pe = match PeFile::parse(&data) {
            Ok(pe) => pe,
            Err(e) => {
                crate::serial_println!("[MODULES] {}: not a usable PE ({}), using built-ins", path, e);
                return Ok(None);
            }
        };
        let (size, stripped) = {
            let pe_off = read_u32(data.as_ptr() as u64 + 0x3C) as usize;
            let opt = pe_off + 24;
            let size = u32::from_le_bytes(data[opt + 56..opt + 60].try_into().map_err(|_| "truncated PE header")?) as u64;
            // IMAGE_FILE_RELOCS_STRIPPED: the image can only run at its preferred base.
            let chars = u16::from_le_bytes(data[pe_off + 22..pe_off + 24].try_into().map_err(|_| "truncated PE header")?);
            (size, chars & 0x0001 != 0)
        };
        let base = if stripped {
            let (lo, hi) = (pe.image_base, pe.image_base + size);
            if lo < 0x1_0000_0000 || self.modules.iter().any(|m| lo < m.base + m.size && m.base < hi) {
                crate::serial_println!("[MODULES] {} can't move (relocations stripped) and its base {:#x} is taken", name, lo);
                return Ok(None);
            }
            lo
        } else if self.base_free(pe.image_base, size) {
            // Its preferred base, as Windows does when it's free: then a DLL
            // is at the same address in every process (the MSYS2 runtime's
            // heap, handed from parent to child, holds pointers into it).
            pe.image_base
        } else {
            let mut b = (self.dll_next + 0xFFFF) & !0xFFFF;
            while !self.base_free(b, size) {
                b = (b + 0x1_0000) & !0xFFFF;
            }
            self.dll_next = b + size;
            b
        };
        Self::map_image(&file, &data, &mut pe, base)?;
        let entry = if pe.entry_point != 0 { base + pe.entry_point } else { 0 };
        let idx = self.push_module(String::from(name), path, base, size, entry, false, pe);
        // Registered before its imports bind, so an import cycle ends here.
        self.bind_imports(mem, idx)?;
        Ok(Some(idx))
    }

    /// Can an image of `size` go at `base`? Not below 4 GiB, nor in the
    /// loader's own regions or the top of the address space, nor over a
    /// module, a range the process uses, or a slot shared with the kernel.
    fn base_free(&self, base: u64, size: u64) -> bool {
        let end = match base.checked_add(size) {
            Some(e) => e,
            None => return false,
        };
        let overlaps = |lo: u64, hi: u64| base < hi && lo < end;
        if base < 0x1_0000_0000 || base & 0xFFFF != 0 || end > 0x7F00_0000_0000 {
            return false;
        }
        // INIT_ENTRY..LOADER_DATA_REGION's end: startup code, thunks, stubs, loader data.
        if overlaps(INIT_ENTRY, LOADER_DATA_REGION + 0x1_0000_0000) {
            return false;
        }
        if self.modules.iter().any(|m| overlaps(m.base, m.base + m.size)) || self.taken.iter().any(|&(lo, hi)| overlaps(lo, hi)) {
            return false;
        }
        let mut p = base & !0x3FFF_FFFF;
        while p < end {
            if crate::address_space::is_kernel_slot(p) {
                return false;
            }
            p += 0x4000_0000;
        }
        true
    }

    /// Where symbols imported from `requested` come from.
    fn provider<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, requested: &str) -> Result<Provider, &'static str> {
        let name = normalize(requested);
        let host = api_set_host(&name);
        let mut real = None;
        if host.is_none() {
            real = self.load_dll(mem, &name)?;
        }
        if real.is_none() {
            if let Some(h) = host {
                real = self.load_dll(mem, h)?;
            }
        }
        let mut builtin = alloc::vec![name.clone()];
        if let Some(h) = host {
            builtin.push(String::from(h));
        }
        Ok(Provider { real, builtin, label: name })
    }

    /// Resolve every import of module `idx` and write its IAT.
    fn bind_imports<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, idx: usize) -> Result<(), &'static str> {
        let base = self.modules[idx].base;
        let imports: Vec<(String, u32, u32)> = self.modules[idx].pe.imports.iter()
            .map(|d| (d.name.clone(), d.original_first_thunk, d.first_thunk)).collect();
        for (dll, oft, ft) in imports {
            let provider = self.provider(mem, &dll)?;
            if let Some(dep) = provider.real {
                if dep != idx && !self.modules[idx].deps.contains(&dep) {
                    self.modules[idx].deps.push(dep);
                }
            }
            let names = base + if oft != 0 { oft } else { ft } as u64;
            let slots = base + ft as u64;
            let mut i = 0u64;
            loop {
                let entry = read_u64(names + i * 8);
                if entry == 0 {
                    break;
                }
                let name_buf;
                let sym = if entry & (1 << 63) != 0 {
                    match api_set_ordinal(&dll, entry as u16) {
                        Some(n) => Sym::Name(n),
                        None => Sym::Ordinal(entry as u16),
                    }
                } else {
                    name_buf = read_cstr(base + (entry & 0x7FFF_FFFF) + 2);
                    Sym::Name(&name_buf)
                };
                let addr = self.resolve(mem, &provider, sym, 0)?;
                write_u64(slots + i * 8, addr);
                i += 1;
            }
        }
        Ok(())
    }

    /// The address an import of `sym` from `p` binds to.
    fn resolve<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, p: &Provider, sym: Sym, depth: u32) -> Result<u64, &'static str> {
        // An unknown API-set ordinal would land on whatever the host DLL
        // numbers that way.
        if matches!(sym, Sym::Ordinal(_)) && api_set_host(&p.label).is_some() {
            return self.unresolved_stub(mem, &p.label, sym);
        }
        if let Some(m) = p.real {
            if let Some(addr) = self.export_address(mem, m, sym, depth)? {
                self.stats.to_modules += 1;
                return Ok(addr);
            }
        }
        if let Some(addr) = self.builtin_address(mem, p, sym)? {
            self.stats.to_builtin += 1;
            return Ok(addr);
        }
        self.unresolved_stub(mem, &p.label, sym)
    }

    /// `sym` in module `m`'s export table, following forwarders.
    fn export_address<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, m: usize, sym: Sym, depth: u32) -> Result<Option<u64>, &'static str> {
        let module = &self.modules[m];
        let rva = match sym {
            // ucrtbase's "_o_" entry points (api-ms-win-crt-private) are its
            // ordinary functions under another name.
            Sym::Name(n) => export_by_name(module.base, module.pe.export_dir, n).or_else(|| {
                n.strip_prefix("_o_").filter(|_| module.name == "ucrtbase.dll").and_then(|plain| export_by_name(module.base, module.pe.export_dir, plain))
            }),
            // Our own system DLLs are numbered by the linker, not as Windows
            // numbers them, except where they say so: an import by number
            // would land on some unrelated function. It's missing instead.
            Sym::Ordinal(_) if !ordinals_are_windows(module) => None,
            Sym::Ordinal(o) => export_by_ordinal(module.base, module.pe.export_dir, o),
        };
        let Some(rva) = rva else { return Ok(None) };
        let base = module.base;
        let forwarded = module.pe.export_dir_range.is_some_and(|(lo, hi)| rva >= lo && rva < hi);
        if !forwarded {
            return Ok(Some(base + rva as u64));
        }
        // A forwarder: "DLL.Name" or "DLL.#ordinal".
        let target = read_cstr(base + rva as u64);
        let from = module.name.clone();
        if depth >= MAX_FORWARD_DEPTH {
            crate::serial_println!("[MODULES] {}!{}: forwarder chain too long ({})", from, sym.describe(), target);
            return Ok(None);
        }
        let Some(dot) = target.rfind('.') else { return Ok(None) };
        let (dll, name) = (&target[..dot], &target[dot + 1..]);
        let provider = self.provider(mem, dll)?;
        let fsym = match name.strip_prefix('#').and_then(|o| o.parse::<u16>().ok()) {
            Some(o) => Sym::Ordinal(o),
            None => Sym::Name(name),
        };
        if let Some(t) = provider.real {
            if let Some(addr) = self.export_address(mem, t, fsym, depth + 1)? {
                return Ok(Some(addr));
            }
        }
        if let Some(addr) = self.builtin_address(mem, &provider, fsym)? {
            return Ok(Some(addr));
        }
        crate::serial_println!("[MODULES] {}!{} forwards to {}, which isn't available", from, sym.describe(), target);
        Ok(None)
    }

    /// A kernel thunk for `sym` if a built-in DLL in `p` provides it.
    fn builtin_address<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, p: &Provider, sym: Sym) -> Result<Option<u64>, &'static str> {
        let wanted = match sym {
            Sym::Name(n) => String::from(n),
            Sym::Ordinal(o) => format!("Ordinal#{}", o),
        };
        // These call back into the program, so they run in user mode.
        match wanted.as_str() {
            "_initterm" if self.overrides.initterm != 0 => return Ok(Some(self.overrides.initterm)),
            "_initterm_e" if self.overrides.initterm_e != 0 => return Ok(Some(self.overrides.initterm_e)),
            _ => {}
        }
        let id = {
            let reg = crate::dll::DLL_REGISTRY.lock();
            p.builtin.iter()
                .filter_map(|n| reg.get_dll(n))
                .find_map(|d| d.symbols.iter().find(|s| s.name == wanted).map(|s| s.syscall_id as u32))
        };
        let Some(id) = id else { return Ok(None) };
        if let Some(&addr) = self.thunk_by_id.get(&id) {
            return Ok(Some(addr));
        }
        let addr = self.thunks.alloc(mem, 16, 16)?;
        let mut code = [0u8; 16];
        code[..6].copy_from_slice(&[0x49, 0x89, 0xCA, 0x48, 0xC7, 0xC0]); // mov r10, rcx; mov rax, imm32
        code[6..10].copy_from_slice(&id.to_le_bytes());
        code[10..13].copy_from_slice(&[0x0F, 0x05, 0xC3]); // syscall; ret
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), addr as *mut u8, 16) };
        self.thunk_by_id.insert(id, addr);
        Ok(Some(addr))
    }

    /// A stub for an import nothing provides: called, it logs "dll!name" once
    /// and returns 0; used as data, it's 32 writable bytes.
    fn unresolved_stub<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, dll: &str, sym: Sym) -> Result<u64, &'static str> {
        let key = format!("{}!{}", dll, sym.describe());
        if let Some(&addr) = self.unresolved_by_name.get(&key) {
            return Ok(addr);
        }
        let id = UNRESOLVED_SYSCALL_BASE + self.unresolved.len() as u64;
        let addr = self.unresolved_slots.alloc(mem, 32, 32)?;
        let mut code = [0u8; 11];
        code[0] = 0xB8; // mov eax, imm32
        code[1..5].copy_from_slice(&(id as u32).to_le_bytes());
        code[5..11].copy_from_slice(&[0x49, 0x89, 0xCA, 0x0F, 0x05, 0xC3]); // mov r10, rcx; syscall; ret
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), addr as *mut u8, code.len()) };
        crate::serial_println!("[MODULES] unresolved: {}", key);
        self.unresolved_by_name.insert(key.clone(), addr);
        self.unresolved.push(key);
        self.stats.unresolved += 1;
        Ok(addr)
    }

    /// Bytes from the loader-data region, 16-aligned.
    fn data_alloc<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, size: u64) -> Result<u64, &'static str> {
        self.data.alloc(mem, size.max(1), 16)
    }

    /// Give module `i` a TLS index if it has a TLS directory, and note its
    /// callbacks. Its data range and zero fill come back for making a block.
    fn assign_tls(&mut self, i: usize) -> Option<(u64, u64, u64)> {
        let base = self.modules[i].base;
        let (rva, size) = data_dir(base, DIR_TLS);
        if rva == 0 || size < 40 {
            return None;
        }
        let dir = base + rva as u64;
        let (start, end, index_addr, callbacks) = (read_u64(dir), read_u64(dir + 8), read_u64(dir + 16), read_u64(dir + 24));
        let zero_fill = read_u32(dir + 32) as u64;
        let index = self.tls_count;
        self.tls_count += 1;
        if index_addr != 0 {
            unsafe { core::ptr::write_unaligned(index_addr as *mut u32, index) };
        }
        let mut cbs = Vec::new();
        if callbacks != 0 {
            for k in 0..64 {
                let cb = read_u64(callbacks + k * 8);
                if cb == 0 {
                    break;
                }
                cbs.push(cb);
            }
        }
        crate::serial_println!("[MODULES] {}: TLS index {}, {} bytes, {} callback(s)", self.modules[i].name, index, end.saturating_sub(start), cbs.len());
        self.modules[i].tls_index = Some(index);
        self.modules[i].tls_callbacks = cbs;
        Some((start, end, zero_fill))
    }

    /// Give every module with a TLS directory an index and a block for the
    /// main thread, and point TEB.ThreadLocalStoragePointer at them. The array
    /// is always there and full size: a DLL loaded later adds to it.
    fn setup_tls<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, teb: u64, peb: u64) -> Result<(), &'static str> {
        let array = self.data_alloc(mem, nt_abi::layout::TLS_ARRAY_SLOTS as u64 * 8)?;
        for i in 0..self.modules.len() {
            let Some((start, end, zero_fill)) = self.assign_tls(i) else { continue };
            let template = end.saturating_sub(start);
            let block = self.data_alloc(mem, template + zero_fill)?;
            if template > 0 {
                unsafe { core::ptr::copy_nonoverlapping(start as *const u8, block as *mut u8, template as usize) };
            }
            write_u64(array + self.modules[i].tls_index.unwrap_or(0) as u64 * 8, block);
        }
        write_u64(teb + 0x58, array); // TEB.ThreadLocalStoragePointer
        write_u64(peb + nt_abi::layout::PEB_MAIN_TLS_ARRAY as u64, array);
        Ok(())
    }

    /// Modules in initialisation order: dependencies before the modules that
    /// import them; the EXE last.
    fn init_order(&self) -> Vec<usize> {
        fn visit(l: &Linker, i: usize, seen: &mut Vec<bool>, out: &mut Vec<usize>) {
            if seen[i] {
                return;
            }
            seen[i] = true;
            for &d in &l.modules[i].deps {
                visit(l, d, seen, out);
            }
            out.push(i);
        }
        let mut seen = alloc::vec![false; self.modules.len()];
        let mut out = Vec::new();
        for i in 0..self.modules.len() {
            visit(self, i, &mut seen, &mut out);
        }
        // The EXE runs last, whatever its index.
        if let Some(p) = out.iter().position(|&i| self.modules[i].is_exe) {
            let exe = out.remove(p);
            out.push(exe);
        }
        out
    }

    /// The startup routine at INIT_ENTRY: TLS callbacks and DllMain for each
    /// module in `order`, then the EXE entry point (RCX = PEB), then
    /// ExitProcess with what it returned. Entered like a function
    /// (RSP = 8 mod 16).
    fn write_startup<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, order: &[usize], peb: u64) -> Result<(), &'static str> {
        let mut code: Vec<u8> = Vec::new();
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28
        let mut calls = 0;
        for &i in order {
            let m = &self.modules[i];
            let mut targets: Vec<u64> = m.tls_callbacks.clone();
            if !m.is_exe && m.entry != 0 {
                targets.push(m.entry);
            }
            for t in targets {
                code.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64 (module handle)
                code.extend_from_slice(&m.base.to_le_bytes());
                code.extend_from_slice(&[0xBA]); // mov edx, imm32 (reason)
                code.extend_from_slice(&(DLL_PROCESS_ATTACH as u32).to_le_bytes());
                // lpReserved: non-NULL for DLLs loaded with the process, as
                // on Windows (Cygwin's DllMain tells static from dynamic
                // loading by it). Programs only test it, so: the PEB.
                code.extend_from_slice(&[0x49, 0xB8]); // mov r8, imm64
                code.extend_from_slice(&peb.to_le_bytes());
                code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
                code.extend_from_slice(&t.to_le_bytes());
                code.extend_from_slice(&[0xFF, 0xD0]); // call rax
                calls += 1;
            }
        }
        // APCs queued during the DllMains run now, before the entry point, as
        // Windows' loader runs them (Cygwin starts its signal thread so).
        if let Some(run_apcs) = self.module_export(mem, "kernel32.dll", "VeilRunApcs") {
            code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
            code.extend_from_slice(&run_apcs.to_le_bytes());
            code.extend_from_slice(&[0xFF, 0xD0]); // call rax
        }
        let exe = self.modules.iter().find(|m| m.is_exe).ok_or("no EXE module")?;
        code.extend_from_slice(&[0x48, 0xB9]); // mov rcx, imm64 (PEB)
        code.extend_from_slice(&peb.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64 (EXE entry)
        code.extend_from_slice(&exe.entry.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]); // call rax
        // The entry point returned: ExitProcess(eax) through the built-in.
        let exit_id = crate::dll::DLL_REGISTRY.lock().get_dll("kernel32.dll")
            .and_then(|d| d.symbols.iter().find(|s| s.name == "ExitProcess").map(|s| s.syscall_id as u32))
            .ok_or("no built-in ExitProcess")?;
        code.extend_from_slice(&[0x89, 0xC1]); // mov ecx, eax
        code.extend_from_slice(&[0x49, 0x89, 0xCA]); // mov r10, rcx
        code.extend_from_slice(&[0xB8]); // mov eax, imm32
        code.extend_from_slice(&exit_id.to_le_bytes());
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0x0F, 0x0B]); // ud2: ExitProcess doesn't return
        let addr = self.init.alloc(mem, code.len() as u64, 16)?;
        debug_assert_eq!(addr, INIT_ENTRY);
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), addr as *mut u8, code.len()) };
        crate::serial_println!("[MODULES] startup: {} init call(s), then {} entry {:#x}", calls, exe.name, exe.entry);
        Ok(())
    }

    /// A UNICODE_STRING buffer holding `s`; returns (buffer, byte length).
    fn utf16<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, s: &str) -> Result<(u64, u16), &'static str> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let buf = self.data_alloc(mem, (units.len() as u64 + 1) * 2)?;
        unsafe { core::ptr::copy_nonoverlapping(units.as_ptr(), buf as *mut u16, units.len()) };
        Ok((buf, (units.len() * 2) as u16))
    }

    /// Fill PEB.Ldr's three module lists.
    fn write_ldr<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, ldr: u64, order: &[usize]) -> Result<(), &'static str> {
        const ENTRY_SIZE: u64 = 0x120;
        let mut entries = Vec::with_capacity(self.modules.len());
        for i in 0..self.modules.len() {
            let e = self.data_alloc(mem, ENTRY_SIZE)?;
            let full = format!("C:{}", self.modules[i].path.replace('/', "\\"));
            let (full_buf, full_len) = self.utf16(mem, &full)?;
            let base_name = self.modules[i].path.rsplit('/').next().unwrap_or("").to_string();
            let (base_buf, base_len) = self.utf16(mem, &base_name)?;
            let m = &self.modules[i];
            unsafe {
                let p = e as *mut u8;
                core::ptr::write_unaligned(p.add(0x30) as *mut u64, m.base); // DllBase
                core::ptr::write_unaligned(p.add(0x38) as *mut u64, m.entry); // EntryPoint
                core::ptr::write_unaligned(p.add(0x40) as *mut u32, m.size as u32); // SizeOfImage
                for (off, buf, len) in [(0x48usize, full_buf, full_len), (0x58, base_buf, base_len)] {
                    core::ptr::write_unaligned(p.add(off) as *mut u16, len); // Length
                    core::ptr::write_unaligned(p.add(off + 2) as *mut u16, len + 2); // MaximumLength
                    core::ptr::write_unaligned(p.add(off + 8) as *mut u64, buf);
                }
                // Flags: LDRP_IMAGE_DLL for DLLs, LDRP_ENTRY_PROCESSED.
                core::ptr::write_unaligned(p.add(0x68) as *mut u32, if m.is_exe { 0 } else { 0x4 } | 0x4000);
                core::ptr::write_unaligned(p.add(0x6C) as *mut u16, 0xFFFF); // ObsoleteLoadCount: static
                core::ptr::write_unaligned(p.add(0x6E) as *mut u16, m.tls_index.map_or(0, |t| t as u16));
                let hash = e + 0x70; // HashLinks: empty
                write_u64(hash, hash);
                write_u64(hash + 8, hash);
            }
            entries.push(e);
        }
        // Each list is circular through its head in PEB_LDR_DATA; the links
        // sit at +0x00 (load order), +0x10 (memory order) and +0x20 (init order)
        // in each entry.
        let link = |head: u64, nodes: &[u64]| {
            let mut prev = head;
            for &n in nodes {
                write_u64(prev, n); // Flink
                write_u64(n + 8, prev); // Blink
                prev = n;
            }
            write_u64(prev, head);
            write_u64(head + 8, prev);
        };
        let load: Vec<u64> = entries.clone();
        let memory: Vec<u64> = entries.iter().map(|e| e + 0x10).collect();
        let init: Vec<u64> = order.iter().filter(|&&i| !self.modules[i].is_exe).map(|&i| entries[i] + 0x20).collect();
        link(ldr + 0x10, &load);
        link(ldr + 0x20, &memory);
        link(ldr + 0x30, &init);
        Ok(())
    }

    /// Final page protection for every module: headers read-only; each section
    /// read-only or writable, executable only if it is code.
    fn protect_images<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&self, mem: &mut Mem<M, F>) {
        // What isn't in yet takes its real protection when it comes in.
        crate::nt_demand::images_linked();
        for m in &self.modules {
            let pages = m.size.div_ceil(4096) as usize;
            // Per page: (writable, executable); pages no section covers stay read-only, NX.
            let mut want = alloc::vec![(false, false); pages];
            for s in &m.pe.sections {
                let len = (s.virtual_size.max(s.size_of_raw_data)) as u64;
                let first = s.virtual_address as u64 / 4096;
                let last = (s.virtual_address as u64 + len).div_ceil(4096);
                let w = s.characteristics & SCN_MEM_WRITE != 0;
                let x = s.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0;
                for p in first..last.min(pages as u64) {
                    want[p as usize].0 |= w;
                    want[p as usize].1 |= x;
                }
            }
            for (p, (w, x)) in want.into_iter().enumerate() {
                let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
                if w {
                    flags |= PageTableFlags::WRITABLE;
                }
                if !x {
                    flags |= PageTableFlags::NO_EXECUTE;
                }
                mem.protect(m.base + p as u64 * 4096, flags);
            }
        }
        // Thunks and the startup routine: read-execute. Loader data: NX.
        let rx = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        for (start, len) in [self.thunks.used(THUNK_REGION), self.init.used(INIT_ENTRY)] {
            for p in 0..(len as u64 / 4096) {
                mem.protect(start + p * 4096, rx);
            }
        }
        let (start, len) = self.data.used(LOADER_DATA_REGION);
        for p in 0..(len as u64 / 4096) {
            mem.protect(start + p * 4096, RW | PageTableFlags::NO_EXECUTE);
        }
    }

    /// Link the EXE (already mapped by `load_exe`): load its DLLs, bind every
    /// import, set up TLS, PEB.Ldr and the startup routine, protect the
    /// images. The program then starts at INIT_ENTRY.
    pub fn link<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, teb: u64, peb: u64, ldr: u64) -> Result<(), &'static str> {
        let exe = self.modules.iter().position(|m| m.is_exe).ok_or("no EXE module")?;
        self.bind_imports(mem, exe)?;
        self.setup_tls(mem, teb, peb)?;
        let order = self.init_order();
        self.ldr = ldr;
        self.initialized = order.clone();
        self.write_ldr(mem, ldr, &order)?;
        self.write_startup(mem, &order, peb)?;
        self.protect_images(mem);
        let names: Vec<&str> = order.iter().map(|&i| self.modules[i].name.as_str()).collect();
        crate::serial_println!("[MODULES] linked {} module(s), init order: {}", self.modules.len(), names.join(", "));
        crate::serial_println!("[MODULES] imports: {} from modules, {} built-in, {} unresolved",
            self.stats.to_modules, self.stats.to_builtin, self.stats.unresolved);
        Ok(())
    }

    /// LoadLibrary: load `name` (a file name or path; the folder is ignored,
    /// DLLs are found as at startup) into the running process. Returns its
    /// base and the init calls (TLS callbacks, then DllMain, dependencies
    /// first) for the caller to run in user mode.
    pub fn load_at_runtime<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, name: &str) -> Result<(u64, Vec<(u64, u64)>), nt_abi::NtStatus> {
        let file = name.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(name);
        let n = normalize(file);
        let first = self.modules.len();
        // A full path means that file. If nothing is there (C:\Windows\System32
        // doesn't exist here), the name is looked for as usual.
        let exact = match crate::nt_file::vfs_path(name) {
            Some(path) if file.len() != name.len() => self.load_dll_at(mem, &path, &n).map_err(|_| nt_abi::status::NO_MEMORY)?,
            _ => None,
        };
        let p = match exact {
            Some(i) => Provider { real: Some(i), builtin: Vec::new(), label: n.clone() },
            None => self.provider(mem, &n).map_err(|_| nt_abi::status::NO_MEMORY)?,
        };
        let Some(idx) = p.real else {
            // Only the kernel's built-ins: a pseudo handle GetProcAddress knows.
            let reg = crate::dll::DLL_REGISTRY.lock();
            if !p.builtin.iter().any(|b| reg.get_dll(b).is_some()) {
                return Err(nt_abi::status::DLL_NOT_FOUND);
            }
            drop(reg);
            let i = match self.builtin_handles.iter().position(|b| *b == n) {
                Some(i) => i,
                None => {
                    self.builtin_handles.push(n.clone());
                    self.builtin_handles.len() - 1
                }
            };
            return Ok((BUILTIN_HANDLE_BASE + i as u64 * 0x10000, Vec::new()));
        };
        if idx < first {
            return Ok((self.modules[idx].base, Vec::new())); // already loaded
        }
        // The newly loaded modules, dependencies first.
        fn visit(l: &Linker, i: usize, first: usize, seen: &mut [bool], out: &mut Vec<usize>) {
            if i < first || seen[i - first] {
                return;
            }
            seen[i - first] = true;
            for &d in &l.modules[i].deps {
                visit(l, d, first, seen, out);
            }
            out.push(i);
        }
        let mut seen = alloc::vec![false; self.modules.len() - first];
        let mut order = Vec::new();
        visit(self, idx, first, &mut seen, &mut order);
        let mut inits = Vec::new();
        for &i in &order {
            // The threads' blocks are ntdll's to make (LdrVeilTlsEnd), before these run.
            self.assign_tls(i);
            if self.tls_count as usize > nt_abi::layout::TLS_ARRAY_SLOTS {
                crate::serial_println!("[MODULES] {}: out of TLS indexes", self.modules[i].name);
                return Err(nt_abi::status::NO_MEMORY);
            }
            let m = &self.modules[i];
            for &cb in &m.tls_callbacks {
                inits.push((cb, m.base));
            }
            if m.entry != 0 {
                inits.push((m.entry, m.base));
            }
        }
        self.initialized.extend_from_slice(&order);
        let (ldr, init_order) = (self.ldr, self.initialized.clone());
        self.write_ldr(mem, ldr, &init_order).map_err(|_| nt_abi::status::NO_MEMORY)?;
        self.protect_images(mem);
        crate::serial_println!("[MODULES] LoadLibrary {}: {} module(s) loaded, {} init call(s)", n, order.len(), inits.len());
        Ok((self.modules[idx].base, inits))
    }

    /// GetProcAddress: `sym` exported by the module at `base` (forwarders
    /// followed), or a built-in with that name. None if neither has it.
    pub fn proc_address<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, base: u64, sym_name: Option<&str>, ordinal: u16) -> Option<u64> {
        let sym = match sym_name {
            Some(n) => Sym::Name(n),
            None => Sym::Ordinal(ordinal),
        };
        let name = if base >= BUILTIN_HANDLE_BASE && base < BUILTIN_HANDLE_BASE + 0x1_0000_0000 {
            self.builtin_handles.get(((base - BUILTIN_HANDLE_BASE) / 0x10000) as usize)?.clone()
        } else {
            let i = self.modules.iter().position(|m| m.base == base)?;
            if let Ok(Some(addr)) = self.export_address(mem, i, sym, 0) {
                return Some(addr);
            }
            self.modules[i].name.clone()
        };
        let mut builtin = alloc::vec![name.clone()];
        if let Some(h) = api_set_host(&name) {
            builtin.push(String::from(h));
        }
        let p = Provider { real: None, builtin, label: name };
        self.builtin_address(mem, &p, sym).ok().flatten()
    }

    /// An export of a loaded module by name ("ntdll.dll", "KiUserExceptionDispatcher"),
    /// without falling back to built-ins.
    pub fn module_export<M: Mapper<Size4KiB>, F: FrameAllocator<Size4KiB>>(&mut self, mem: &mut Mem<M, F>, dll: &str, sym: &str) -> Option<u64> {
        let i = self.modules.iter().position(|m| m.name == dll)?;
        self.export_address(mem, i, Sym::Name(sym), 0).ok().flatten()
    }

    /// Every region the loader mapped, for the process's VAD (so VirtualAlloc
    /// never hands them out).
    pub fn regions(&self) -> Vec<(u64, usize)> {
        let mut r: Vec<(u64, usize)> = self.modules.iter().map(|m| (m.base, m.size as usize)).collect();
        for (start, b) in [(INIT_ENTRY, &self.init), (THUNK_REGION, &self.thunks), (UNRESOLVED_REGION, &self.unresolved_slots), (LOADER_DATA_REGION, &self.data)] {
            let (s, len) = b.used(start);
            if len > 0 {
                r.push((s, len));
            }
        }
        r
    }
}

/// Apply an image's base relocations for loading at `actual_base` (its
/// pages must be mapped and writable). Returns the number of fixups.
pub fn apply_base_relocations(pe: &PeFile, data: &[u8], actual_base: u64) -> usize {
    const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
    const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
    const IMAGE_REL_BASED_DIR64: u16 = 10;

    let delta = actual_base.wrapping_sub(pe.image_base);
    if delta == 0 {
        return 0;
    }
    // No table: nothing in the image needs fixing (a stripped image is never
    // moved, see `load_dll`).
    let Some((reloc_rva, reloc_size)) = pe.reloc_dir else { return 0 };
    let Some(mut off) = PeFile::rva_to_offset(&pe.sections, reloc_rva) else { return 0 };
    let end = off + reloc_size as usize;
    let mut fixups = 0usize;
    while off + 8 <= end && off + 8 <= data.len() {
        let page_rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let block = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if block < 8 || off + block > data.len() {
            break;
        }
        for i in 0..(block - 8) / 2 {
            let e = u16::from_le_bytes(data[off + 8 + i * 2..off + 10 + i * 2].try_into().unwrap());
            let target = actual_base + page_rva as u64 + (e & 0x0FFF) as u64;
            match e >> 12 {
                IMAGE_REL_BASED_ABSOLUTE => {}
                IMAGE_REL_BASED_DIR64 => {
                    write_u64(target, read_u64(target).wrapping_add(delta));
                    fixups += 1;
                }
                IMAGE_REL_BASED_HIGHLOW => unsafe {
                    let p = target as *mut u32;
                    core::ptr::write_unaligned(p, core::ptr::read_unaligned(p).wrapping_add(delta as u32));
                    fixups += 1;
                },
                other => crate::serial_println!("[MODULES] unsupported relocation type {} at {:#X}", other, target),
            }
        }
        off += block;
    }
    fixups
}

/// `dll!name` of unresolved stub `id` for the current process, the first time
/// it is called (later calls return None, so each is logged once).
/// The "dll!name" behind a missing import's syscall, whether or not it was
/// called before.
pub fn unresolved_name(id: u64) -> Option<String> {
    let proc = crate::process::PROCESSOR.lock().get_active()?;
    let names = proc.unresolved_imports.lock();
    names.get((id - UNRESOLVED_SYSCALL_BASE) as usize).map(|e| e.0.clone())
}

pub fn unresolved_call(id: u64) -> Option<String> {
    let proc = crate::process::PROCESSOR.lock().get_active()?;
    let mut names = proc.unresolved_imports.lock();
    let entry = names.get_mut((id - UNRESOLVED_SYSCALL_BASE) as usize)?;
    if entry.1 {
        return None;
    }
    entry.1 = true;
    Some(entry.0.clone())
}
