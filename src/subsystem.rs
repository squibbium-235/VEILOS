use crate::println;
use crate::nt_objects;
use crate::nt_memory;
use crate::nt_thread;
use crate::win32_user;

// ---------------------------------------------------------------------------
// CRT heap allocation tracker
// ---------------------------------------------------------------------------
// malloc / calloc allocate page-aligned regions from bump-pointer arenas.
// Because the underlying frame allocator is a bump allocator with no free(),
// we can't return physical frames to the OS pool — but we CAN unmap the
// virtual pages so (a) the address space doesn't exhaust and (b) the physical
// frames are at least not accessible through that address any longer, which
// prevents use-after-free information leaks.
//
// The tracker maps  virtual_base → page_count  for every live CRT allocation.
// free() looks up the entry, writes zeros over every page (defensive), then
// calls Mapper::unmap() + TlbFlush on each page to remove the PTE.
// ---------------------------------------------------------------------------

use alloc::collections::BTreeMap;
use spin::Mutex;

static CRT_ALLOC_MAP: Mutex<BTreeMap<u64, usize>> = Mutex::new(BTreeMap::new());

/// Fetch a copy of the active process's NT environment (TEB/PEB/_initterm
/// trampoline addresses, __argc/__argv data pointers).
///
/// These used to live in `crate::loader::{INITTERM_ADDR, ARGC_PTR_ADDR,
/// ARGV_PTR_ADDR, ...}` as bare `static mut` globals shared by every
/// process — which is exactly what made the IAT linker fragile across
/// relaunches. They now live on `Process::nt_env`, set once by the loader
/// before the IAT is linked. `NtEnv` is `Copy`, so this is a cheap lock-clone
/// rather than holding the process lock for the caller's whole match arm.
/// Returns `NtEnv::default()` (all zeros) if there is no active process,
/// matching the old code's implicit "0 means not set yet" behaviour.
fn active_nt_env() -> crate::loader::NtEnv {
    crate::process::PROCESSOR.lock()
        .get_active()
        .map(|p| *p.nt_env.lock())
        .unwrap_or_default()
}

/// Record a new CRT allocation so free() can find its page count.
fn crt_track_alloc(base: u64, num_pages: usize) {
    CRT_ALLOC_MAP.lock().insert(base, num_pages);
}

/// Unmap and de-register a CRT allocation.  Returns true if the address was
/// found in the tracker (i.e. it was a valid live allocation).
fn crt_free(base: u64) -> bool {
    let num_pages = match CRT_ALLOC_MAP.lock().remove(&base) {
        Some(n) => n,
        None    => return false, // not a tracked CRT allocation — ignore
    };

    if num_pages == 0 || base < 0x1000 { return true; }

    unsafe {
        use x86_64::structures::paging::{Mapper, Page};
        use x86_64::VirtAddr;

        let mut mapper = crate::memory::get_mapper();

        for i in 0..num_pages {
            let vaddr = VirtAddr::new(base + i as u64 * 4096);
            let page  = Page::<x86_64::structures::paging::Size4KiB>::containing_address(vaddr);

            // Zero the page contents before unmapping so physical frames
            // can't be read through a future alias (defensive scrubbing).
            core::ptr::write_bytes(vaddr.as_mut_ptr::<u8>(), 0, 4096);

            // Remove the PTE.  unmap() returns the frame + flush token;
            // we flush immediately and let the frame stay in the bump
            // allocator's used-but-unmapped pool (no deallocate_frame).
            if let Ok((_frame, flush)) = mapper.unmap(page) {
                flush.flush();
            }
        }
    }
    true
}

// -----| subsystem personalities |-----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsystemType {
    VeilosNative,
    WindowsNT,
    LegacyDOS,
}

pub trait Subsystem: Send + Sync {
    fn get_type(&self) -> SubsystemType;
    fn handle_syscall(&self, id: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64;
    /// Optional: called on every scheduler tick to allow the subsystem to perform background work.
    fn tick(&self) -> Option<&'static str> { None }
}

// -----| kernel / nul subsystem |-----

pub struct NoopSubsystem;

impl Subsystem for NoopSubsystem {
    fn get_type(&self) -> SubsystemType { SubsystemType::VeilosNative }

    fn handle_syscall(&self, _id: u64, _arg0: u64, _arg1: u64, _arg2: u64, _arg3: u64) -> u64 {
        0u64
    }
}


// -----| native veilos subsystem |-----

pub struct NativeSubsystem;

impl Subsystem for NativeSubsystem {
    fn get_type(&self) -> SubsystemType { SubsystemType::VeilosNative }

    fn handle_syscall(&self, id: u64, arg0: u64, arg1: u64, arg2: u64, _arg3: u64) -> u64 {
        // Route all VEILOS native syscalls (0x5000–0x5FFF) to the SDK dispatcher.
        if id >= 0x5000 && id <= 0x5FFF {
            return crate::toolchain::dispatch_native_syscall(id, arg0, arg1, arg2);
        }
        match id {
            1 => { println!("[NATIVE] sys_write: buffer at {:#X}", arg0); 0 }
            _ => { println!("[NATIVE] Unknown syscall: {:#x}", id); u64::MAX }
        }
    }
}

// -----| windows nt subsystem |-----

pub struct WindowsSubsystem;

/// Allocate a zeroed page for a threadpool object stub.
/// Returns a pointer to 4096 zeroed bytes so callers can safely
/// read/write any field offset without faulting.
fn tpool_alloc() -> u64 {
    static TPOOL_BUMP: core::sync::atomic::AtomicU64 =
        core::sync::atomic::AtomicU64::new(0xB_0000_0000);
    let addr = TPOOL_BUMP.fetch_add(0x2000, core::sync::atomic::Ordering::Relaxed); // 4K obj + 4K guard
    let mut mapper = unsafe { crate::memory::get_mapper() };
    let mut fa = crate::memory::GlobalFrameAllocator;
    let page = x86_64::structures::paging::Page::containing_address(
        x86_64::VirtAddr::new(addr));
    if let Some(frame) = crate::memory::allocate_frame() {
        crate::memory::map_page(page, frame,
            x86_64::structures::paging::PageTableFlags::PRESENT |
            x86_64::structures::paging::PageTableFlags::WRITABLE |
            x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE,
            &mut mapper, &mut fa);
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096); }
        addr
    } else {
        0
    }
}

/// An OutputDebugString argument: ASCII, or UTF-16 if its second byte is 0.
/// At most 256 characters; bytes outside the caller's mapped memory end it.
fn read_debug_string(ptr: u64) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    if !crate::memory::user_ptr_ok(ptr, 2) {
        return s;
    }
    let wide = unsafe { *((ptr + 1) as *const u8) } == 0;
    let step = if wide { 2 } else { 1 };
    for i in 0..256u64 {
        let addr = ptr + i * step;
        if !crate::memory::user_ptr_ok(addr, step as usize) {
            break;
        }
        let c = if wide { (unsafe { core::ptr::read_unaligned(addr as *const u16) }) as u32 } else { (unsafe { *(addr as *const u8) }) as u32 };
        if c == 0 {
            break;
        }
        s.push(char::from_u32(c).unwrap_or('?'));
    }
    s
}

/// A program called an import nothing provides. Windows wouldn't have
/// started it ("entry point not found"); VEILOS starts it, in case it never
/// makes the call, and ends it with that status if it does, saying which
/// function on its console, on the desktop and in the log. Answering 0
/// instead was quiet and sometimes wrong: git saved a corrupt index on
/// htons's 0, curl believed a CNG 0 meant success. VEILOS_MISSING_CALLS=zero
/// in a program's environment brings that back, for trying new programs.
fn missing_call(id: u64) -> u64 {
    const STATUS_ENTRYPOINT_NOT_FOUND: i32 = 0xC000_0139u32 as i32;
    let Some(proc) = crate::process::PROCESSOR.lock().get_active() else { return 0 };
    if proc.missing_calls_return_zero.load(core::sync::atomic::Ordering::Relaxed) {
        if let Some(name) = crate::modules::unresolved_call(id) {
            crate::serial_println!("[WIN32] called unresolved import {} (returns 0: VEILOS_MISSING_CALLS=zero)", name);
        }
        return 0;
    }
    let name = crate::modules::unresolved_name(id).unwrap_or_else(|| {
        alloc::format!(
            "an unknown function (missing syscall {:#x}, slot {})",
            id,
            id - crate::modules::UNRESOLVED_SYSCALL_BASE
        )
    });
    let program = proc.linker.lock().as_ref().and_then(|l| l.exe_name()).unwrap_or_else(|| alloc::string::String::from(proc.name));
    crate::serial_println!("[WIN32] pid {} ({}) called {}, which VEILOS doesn't have: ending it", proc.pid, program, name);
    if let Some(console) = &proc.console {
        let text = alloc::format!(
            "\r\nVEILOS: this program called {}, which isn't implemented yet, so it was stopped.\r\n(Set VEILOS_MISSING_CALLS=zero to let missing calls return 0 instead.)\r\n",
            name
        );
        console.write(text.as_bytes());
    }
    crate::desktop::notify(
        crate::desktop::NotifCategory::Error,
        &alloc::format!("{} stopped", program),
        &alloc::format!("It called {}, which VEILOS doesn't have yet.", name),
    );
    crate::serial_println!("[NT] pid {} exits with code {}", proc.pid, STATUS_ENTRYPOINT_NOT_FOUND);
    crate::nt_process::kill_process(&proc, STATUS_ENTRYPOINT_NOT_FOUND);
    unsafe { crate::loader::return_from_usermode() }
}

impl Subsystem for WindowsSubsystem {
    fn get_type(&self) -> SubsystemType { SubsystemType::WindowsNT }

    fn handle_syscall(&self, id: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {

        // ---- NT system services for VEILOS's ntdll.dll ----
        if crate::nt_syscalls::handles(id) {
            return crate::nt_syscalls::dispatch(id, arg0, arg1, arg2, arg3);
        }

        // ---- An import nothing provides (modules.rs stub) ----
        if (crate::modules::UNRESOLVED_SYSCALL_BASE..crate::modules::UNRESOLVED_SYSCALL_BASE + 0x0100_0000).contains(&id) {
            return missing_call(id);
        }

        // ---- Anti-Cheat compatibility layer (Phase 14) ----
        // Intercepts AC-specific syscalls before the standard NT dispatcher.
        if let Some(result) = crate::anticheat::dispatch_ac_syscall(id, arg0, arg1, arg2) {
            return result;
        }

        // ---- NT Object Manager (Phase 5a) ----
        match id {
            0x04 | 0x05 | 0x0E | 0x0F | 0x9D |
            0x48 | 0x78 | 0x5C | 0x77 | 0xAB |
            0x5E | 0x7A | 0xAC | 0x4A | 0x79 | 0xCE
            => return nt_objects::dispatch_nt_object_syscall(id, arg0, arg1, arg2),
            _ => {}
        }

        // ---- NT Memory Manager (Phase 5b) ----
        // arg3 used to be hardcoded to 0 here, so NtAllocateVirtualMemory's
        // `protect` parameter (PAGE_READWRITE / PAGE_EXECUTE_READWRITE / ...)
        // was always lost — every allocation got whatever nt_memory's default
        // happened to be, regardless of what the app asked for.
        match id {
            0x0018 | 0x001E | 0x0050 | 0x0023 | 0x0028 | 0x002A
            => return nt_memory::dispatch_nt_memory_syscall(id, arg0, arg1, arg2, arg3),
            _ => {}
        }

        // ---- NT Thread Subsystem (Phase 5c) ----
        match id {
            0x4B | 0x52 | 0x53 | 0x188 |
            0x3001 | 0x3002 | 0x3003 |
            0x3010 | 0x3011 | 0x3012 | 0x3013
            => return nt_thread::dispatch_nt_thread_syscall(id, arg0, arg1, arg2),
            _ => {}
        }

        // ---- Win32 User Subsystem (Phase 5d) ----
        if id >= 0x4001 && id <= 0x401F {
            return win32_user::dispatch_win32_user_syscall(id, arg0, arg1, arg2, arg3);
        }

        // ---- kernel32.dll high-level stubs ----
        match id {
            0x1001 => { println!("[KERNEL32] GetStdHandle({})", arg0); 7 }
            0x1002 => { 
                let addr = arg1;
                let len  = arg2 as usize;
                let mut text = alloc::string::String::new();
                // `addr` is a raw user-mode buffer pointer supplied by the app.
                // The old loop read it unchecked, so a bad lpBuffer here
                // page-faulted mid-syscall.
                if crate::memory::user_ptr_ok(addr, len.max(1)) {
                    for i in 0..len {
                        let byte = unsafe { core::ptr::read_volatile((addr + i as u64) as *const u8) };
                        if byte == 0 { break; }
                        text.push(byte as char);
                    }
                } else if len > 0 {
                    crate::serial_println!("[KERNEL32] WriteConsoleA: bad buffer {:#X} len {}", addr, len);
                }
                println!("[KERNEL32] WriteConsoleA: {}", text);
                for slot in &crate::apps::TERMINAL_POOL {
                    if let Some(mut term) = slot.try_lock() {
                        if term.window_id != 0 {
                            term.history.push(text.clone());
                        }
                    }
                }
                nt_objects::STATUS_SUCCESS 
            }
            0x1003 => {
                println!("[KERNEL32] ExitProcess({})", arg0);
                crate::serial_println!("[KERNEL32] ExitProcess({})", arg0);
                if let Some(proc) = crate::process::PROCESSOR.lock().get_active() {
                    proc.terminate(arg0 as i32);
                }
                crate::interrupts::USER_PROCESS_ACTIVE.store(false, core::sync::atomic::Ordering::Relaxed);
                unsafe { crate::loader::return_from_usermode() }
            }
            
            // --- Kernel32 Object Wrappers ---
            0x100A => nt_objects::dispatch_nt_object_syscall(0xAB, arg0, 0, 0),
            0x100B => nt_objects::dispatch_nt_object_syscall(0x5E, 0, arg0, arg1),
            0x100C => nt_objects::dispatch_nt_object_syscall(0xAC, arg0, arg1, 0),
            0x100D => nt_objects::dispatch_nt_object_syscall(0x4A, 0, arg0, arg1),

            // --- Module & Process Management ---
            0x1004 => { 
                if let Some(proc) = crate::process::PROCESSOR.lock().get_active() {
                    proc.image_base // GetModuleHandle(NULL): the EXE's base
                } else { 0 }
            }
            0x1005 => { println!("[KERNEL32] GetProcAddress"); 0 }
            0x1006 => crate::process::PROCESSOR.lock().get_active().map_or(0, |p| p.pid) as u64,
            0x1007 => 1,
            0x1008 => 0x400000, 

            // --- Memory Management ---
            0x1010 => {
                // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
                let size = arg1 as usize;
                if size == 0 { return 0; }
                let mut mapper = unsafe { crate::memory::get_mapper() };
                let mut fa     = crate::memory::GlobalFrameAllocator;
                let num_pages = core::cmp::max((size + 4095) / 4096, 1);
                // Was `static mut` — a plain global bumped without
                // synchronisation.  Two CPUs (or two threads on this core, if
                // preemption is ever added) calling VirtualAlloc concurrently
                // could hand out the same address twice.  This never freed
                // address space either (matching real VirtualAlloc's model of
                // reserve+commit is a bigger job than the current bug hunt),
                // but it is at least now safe to call from more than one place.
                static VALLOC_PTR: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0x9_0000_0000);
                let addr = if arg0 != 0 {
                    arg0
                } else {
                    VALLOC_PTR.fetch_add(
                        (num_pages as u64 * 4096) + 4096,
                        core::sync::atomic::Ordering::Relaxed,
                    )
                };
                for i in 0..num_pages {
                    let page = x86_64::structures::paging::Page::containing_address(
                        x86_64::VirtAddr::new(addr + (i as u64 * 4096)));
                    if let Some(frame) = crate::memory::allocate_frame() {
                        crate::memory::map_page(page, frame,
                            x86_64::structures::paging::PageTableFlags::PRESENT |
                            x86_64::structures::paging::PageTableFlags::WRITABLE |
                            x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE,
                            &mut mapper, &mut fa);
                    } else { return 0; }
                }
                // Zero the allocated memory (MEM_COMMIT zeroes pages)
                unsafe { core::ptr::write_bytes(addr as *mut u8, 0, num_pages * 4096); }
                addr
            }
            0x1011 => nt_memory::dispatch_nt_memory_syscall(0x001E, arg0, arg1, arg2, 0),
            0x1012 => nt_memory::dispatch_nt_memory_syscall(0x0050, arg0, arg1, arg2, 0),
            0x1013 => {
                // HeapAlloc(hHeap, dwFlags, dwBytes)
                // Route through same allocator as malloc
                let size = arg2 as usize;
                if size == 0 { return 0; }
                let flags = arg1 as u32;
                let mut mapper = unsafe { crate::memory::get_mapper() };
                let mut fa     = crate::memory::GlobalFrameAllocator;
                let num_pages = core::cmp::max((size + 4095) / 4096, 1);
                static HEAP_ALLOC_PTR: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0x9_8000_0000);
                let addr = HEAP_ALLOC_PTR.fetch_add(
                    (num_pages as u64 * 4096) + 4096,
                    core::sync::atomic::Ordering::Relaxed,
                );
                for i in 0..num_pages {
                    let page = x86_64::structures::paging::Page::containing_address(
                        x86_64::VirtAddr::new(addr + (i as u64 * 4096)));
                    if let Some(frame) = crate::memory::allocate_frame() {
                        crate::memory::map_page(page, frame,
                            x86_64::structures::paging::PageTableFlags::PRESENT |
                            x86_64::structures::paging::PageTableFlags::WRITABLE |
                            x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE,
                            &mut mapper, &mut fa);
                    } else { return 0; }
                }
                // HEAP_ZERO_MEMORY flag = 0x08
                if flags & 0x08 != 0 {
                    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, num_pages * 4096); }
                }
                addr
            }

            // --- Threading & Sync ---
            0x1020 => nt_thread::dispatch_nt_thread_syscall(0x4B, arg0, arg1, arg2),
            // ── CRITICAL_SECTION (0x1021–0x1025) ──────────────────────────────
            // InitializeCriticalSection(lpCriticalSection)
            // Fills the CRITICAL_SECTION struct in-place.
            // x64 layout (40 bytes):
            //   +0x00  DebugInfo ptr  (PRTL_CRITICAL_SECTION_DEBUG) — set to 0xFFFFFFFFFFFFFFFF
            //   +0x08  LockCount      (LONG) — must be -1 (0xFFFFFFFF) when unlocked
            //   +0x0C  RecursionCount (LONG) — 0 when unlocked
            //   +0x10  OwningThread   (HANDLE) — 0 when unlocked
            //   +0x18  LockSemaphore  (HANDLE) — 0 (no kernel event needed single-threaded)
            //   +0x20  SpinCount      (ULONG_PTR)
            0x1021 => {
                if arg0 > 0x1000 {
                    let cs = arg0 as *mut u64;
                    unsafe {
                        *cs.add(0) = 0xFFFF_FFFF_FFFF_FFFFu64; // DebugInfo = -1 (no debug)
                        *cs.add(1) = 0x0000_0000_FFFF_FFFFu64; // LockCount=-1 | RecursionCount=0
                        *cs.add(2) = 0u64;  // OwningThread = NULL
                        *cs.add(3) = 0u64;  // LockSemaphore = NULL
                        *cs.add(4) = 0u64;  // SpinCount = 0
                    }
                }
                0
            }
            // InitializeCriticalSectionEx(lp, dwSpinCount, flags) — delegates to 0x1021
            // EnterCriticalSection — single-threaded: always succeeds immediately
            0x1022 => {
                if arg0 > 0x1000 {
                    unsafe {
                        // Set LockCount to 0 (locked once) and OwningThread to our fake TID
                        let cs = arg0 as *mut i32;
                        *cs.add(2) = 0;   // LockCount = 0
                        *cs.add(3) += 1;  // RecursionCount++
                    }
                }
                0
            }
            // LeaveCriticalSection — single-threaded: always succeeds
            0x1023 => {
                if arg0 > 0x1000 {
                    unsafe {
                        let cs = arg0 as *mut i32;
                        *cs.add(3) -= 1;  // RecursionCount--
                        if *cs.add(3) <= 0 {
                            *cs.add(2) = -1; // LockCount back to -1 (unlocked)
                            *cs.add(3) = 0;
                        }
                    }
                }
                0
            }
            0x1024 => {
                println!("[KERNEL32] Sleep({})", arg0);
                0
            }
            // DeleteCriticalSection — zero the struct so stale pointers crash cleanly
            0x1025 => {
                if arg0 > 0x1000 {
                    unsafe { core::ptr::write_bytes(arg0 as *mut u8, 0, 40); }
                }
                0
            }
            // InitializeCriticalSectionAndSpinCount / Ex
            0x1086 => {
                // Same as InitializeCriticalSection but with spin count (arg1)
                if arg0 > 0x1000 {
                    let cs = arg0 as *mut u64;
                    unsafe {
                        *cs.add(0) = 0xFFFF_FFFF_FFFF_FFFFu64;
                        *cs.add(1) = 0x0000_0000_FFFF_FFFFu64;
                        *cs.add(2) = 0u64;
                        *cs.add(3) = 0u64;
                        *cs.add(4) = arg1; // SpinCount
                    }
                }
                1 // returns TRUE
            }

            // ── kernel32 extras ──────────────────────────────────────────────
            // Handle management
            0x1030 => { 1 }  // CloseHandle → TRUE
            0x1031 => { 0xFFFF_FFFF_FFFF_FFFFu64 }  // GetCurrentProcess → pseudo-handle (-1)
            0x1032 => { 1 }  // DuplicateHandle → TRUE (stub, doesn't actually duplicate)
            0x1033 => { 1 }  // SetHandleInformation → TRUE
            0x1034 => { 1 }  // GetProcessHeap → fake heap handle (1)
            0x1035 => {       // HeapReAlloc(heap, flags, ptr, size) — realloc via page alloc
                // For now return the existing pointer unchanged (safe if size ≤ original).
                // A real implementation would copy to a new region.
                arg2  // Return original pointer
            }
            // Error
            0x1040 => { 0 }  // GetLastError → 0 (ERROR_SUCCESS)
            0x1041 => { 0 }  // SetLastError → void, return 0
            0x1042 => {       // GetModuleFileNameW → write L"VEILAPP" to buffer
                if arg1 > 0x1000 {
                    let buf = arg1 as *mut u16;
                    let name: &[u16] = &[b'V' as u16, b'E' as u16, b'I' as u16, b'L' as u16, 0];
                    unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), buf, name.len()); }
                }
                4  // len
            }
            0x1043 => { 0 }  // IsProcessorFeaturePresent → FALSE (safe default)
            0x1044 => { 0 }  // IsDebuggerPresent → FALSE
            0x1045 => { 0 }  // UnhandledExceptionFilter → EXCEPTION_CONTINUE_SEARCH
            0x1046 => { 0 }  // SetUnhandledExceptionFilter → NULL (prev filter)
            0x1047 => { 1 }  // AddVectoredExceptionHandler → non-null (fake handle)
            // Time
            0x1050 => {       // QueryPerformanceCounter → write tick count to *arg0
                let ticks = crate::interrupts::TICKS.load(core::sync::atomic::Ordering::Relaxed);
                if arg0 > 0x1000 { unsafe { *(arg0 as *mut u64) = ticks; } }
                1  // TRUE
            }
            0x1051 => {       // QueryPerformanceFrequency → write 1_000_000 (1MHz) to *arg0
                if arg0 > 0x1000 { unsafe { *(arg0 as *mut u64) = 1_000_000; } }
                1
            }
            0x1052 => {       // GetSystemTimeAsFileTime → write FILETIME to *arg0
                // FILETIME = 100ns intervals since Jan 1 1601.
                // Approximate: use tick counter * 10000 (ms→100ns) + epoch offset.
                let ticks = crate::interrupts::TICKS.load(core::sync::atomic::Ordering::Relaxed);
                let filetime: u64 = 132_000_000_000_000_000u64 + ticks * 10_000;
                if arg0 > 0x1000 { unsafe { *(arg0 as *mut u64) = filetime; } }
                0
            }
            // String / encoding
            0x1060 => {       // WideCharToMultiByte — naive: copy low byte of each wchar
                let src_w = arg1 as *const u16;
                let src_len = arg2 as usize;
                let dst = arg3 as *mut u8;
                let dst_len = {
                    // arg4 / arg5 passed on Windows stack — unreachable; use src_len
                    core::cmp::min(src_len, 256)
                };
                if src_w as u64 > 0x1000 && dst as u64 > 0x1000 {
                    for i in 0..dst_len {
                        let wc = unsafe { *src_w.add(i) };
                        unsafe { *dst.add(i) = (wc & 0xFF) as u8; }
                    }
                }
                dst_len as u64
            }
            0x1061 => {       // MultiByteToWideChar — naive: zero-extend each byte
                let src = arg1 as *const u8;
                let src_len = arg2 as usize;
                let dst_w = arg3 as *mut u16;
                let out_len = core::cmp::min(src_len, 256);
                if src as u64 > 0x1000 && dst_w as u64 > 0x1000 {
                    for i in 0..out_len {
                        let b = unsafe { *src.add(i) };
                        unsafe { *dst_w.add(i) = b as u16; }
                    }
                }
                out_len as u64
            }
            0x1062 => {       // lstrlenW
                if arg0 < 0x1000 { return 0; }
                let ptr = arg0 as *const u16;
                let mut len = 0usize;
                while len < 65535 && unsafe { *ptr.add(len) } != 0 { len += 1; }
                len as u64
            }
            0x1063 => { 0 }  // CompareStringOrdinal → CSTR_EQUAL(2) or 0 stub
            0x1064 => { 0 }  // FormatMessageW → 0 (fail)
            // Global heap
            0x1070 => {       // GlobalAlloc(flags, size) — route through our malloc stub
                let size = arg1 as usize;
                if size == 0 { return 0; }
                // Reuse 0x9001 (malloc) logic inline
                let mut mapper = unsafe { crate::memory::get_mapper() };
                let mut fa = crate::memory::GlobalFrameAllocator;
                let num_pages = (size + 4095) / 4096;
                static GLOBAL_ALLOC_PTR: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0xA_0000_0000);
                let addr = GLOBAL_ALLOC_PTR.fetch_add(
                    (num_pages as u64 * 4096) + 4096,
                    core::sync::atomic::Ordering::Relaxed,
                );
                for i in 0..num_pages {
                    let page = x86_64::structures::paging::Page::containing_address(
                        x86_64::VirtAddr::new(addr + i as u64 * 4096));
                    let frame = match crate::memory::allocate_frame() {
                        Some(f) => f,
                        None => { crate::serial_println!("[UCRT] GlobalAlloc: out of frames"); return 0; }
                    };
                    crate::memory::map_page(page, frame,
                        x86_64::structures::paging::PageTableFlags::PRESENT |
                        x86_64::structures::paging::PageTableFlags::WRITABLE |
                        x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE,
                        &mut mapper, &mut fa);
                }
                // Zero pages — frames contain physical memory leftovers.
                if num_pages > 0 {
                    unsafe { core::ptr::write_bytes(addr as *mut u8, 0, num_pages * 4096); }
                }
                addr
            }
            0x1071 => { 1 }  // GlobalFree → NULL on success
            0x1072 => { arg0 }  // GlobalLock → return the pointer itself (no locking needed)
            0x1073 => { 1 }  // GlobalUnlock → TRUE
            0x1074 => { 4096 }  // GlobalSize → return 4096 as conservative estimate
            0x1075 => { 0 }  // InitializeSListHead → void
            // Threading extras
            0x1080 => { 2 }  // GetCurrentThread → pseudo-handle (2, distinct from -1)
            0x1081 | 0x1082 => { 0 }  // WaitForSingleObject/Ex → WAIT_OBJECT_0
            0x1083 => { 1 }  // CreateMutexA → fake handle
            0x1084 => { 1 }  // ReleaseMutex → TRUE
            0x1085 => { 1 }  // SwitchToThread → TRUE
            0x1124 => { 0 }  // SleepEx → 0 (WAIT_OBJECT_0)
            0x1087 => { 1 }  // SetThreadStackGuarantee → TRUE
            0x1088 => { 0 }  // SetThreadErrorMode → old mode (0)
            0x1090 => { 1 }  // CreateWaitableTimerExW → fake handle
            0x1091 => { 1 }  // SetWaitableTimer → TRUE
            // Library loading
            0x10A0 => { 1 }  // LoadLibrary* → fake module handle (non-null)
            0x10A1 => { 1 }  // FreeLibrary → TRUE
            // System info
            0x10B0 => {       // GetSystemInfo → write minimal SYSTEM_INFO struct to *arg0
                // SYSTEM_INFO layout (simplified 64-bit relevant fields):
                //  +0x00  dwOemId / wProcessorArchitecture = 9 (PROCESSOR_ARCHITECTURE_AMD64)
                //  +0x04  dwPageSize = 4096
                //  +0x08  lpMinimumApplicationAddress = 0x10000
                //  +0x10  lpMaximumApplicationAddress = 0x7FFFFFFFFFFF
                //  +0x18  dwActiveProcessorMask = 1
                //  +0x20  dwNumberOfProcessors = 1
                //  +0x24  dwProcessorType = 8664
                //  +0x28  dwAllocationGranularity = 65536
                if arg0 > 0x1000 {
                    let p = arg0 as *mut u32;
                    unsafe {
                        *p.add(0)  = 9u32;          // PROCESSOR_ARCHITECTURE_AMD64 in low word
                        *p.add(1)  = 4096u32;        // dwPageSize
                        *(arg0 as *mut u64).add(1) = 0x10000u64;   // lpMinimumApplicationAddress
                        *(arg0 as *mut u64).add(2) = 0x7FFF_FFFF_FFFFu64; // lpMaximumApplicationAddress
                        *(arg0 as *mut u64).add(3) = 1u64;          // dwActiveProcessorMask
                        *p.add(8)  = 1u32;           // dwNumberOfProcessors
                        *p.add(9)  = 8664u32;        // dwProcessorType
                        *p.add(10) = 65536u32;       // dwAllocationGranularity
                    }
                }
                0
            }
            0x10B1 => { 0 }  // GetEnvironmentVariableW → 0 (not found)
            0x10B2 => { 0 }  // GetEnvironmentStringsW → NULL
            0x10B3 => { 1 }  // FreeEnvironmentStringsW → TRUE
            0x10B4 => { 0 }  // GetCurrentDirectoryW → 0
            0x10B5 | 0x10B6 => { 0 }  // GetWindowsDirectoryW / GetSystemDirectoryW → 0
            0x10B7 => { 437 }  // GetConsoleOutputCP → CP_OEM (437)
            0x10B8 => { 0 }  // GetConsoleMode → 0 (not a console)
            0x10B9 => { 0 }  // GetExitCodeProcess → 0 (STILL_ACTIVE would be 259)
            // File I/O stubs — return INVALID_HANDLE_VALUE or 0
            0x10C0 => { 0xFFFF_FFFF_FFFF_FFFFu64 }  // CreateFileW → INVALID_HANDLE_VALUE
            0x10C1 | 0x10C2 => { 0 }  // ReadFileEx / WriteFileEx → 0 (fail)
            0x10C3 => { 0 }  // DeleteFileW → FALSE
            0x10C4 => { 0xFFFF_FFFF_FFFF_FFFFu64 }  // FindFirstFileExW → INVALID_HANDLE_VALUE
            0x10C5 => { 0 }  // FindNextFileW → FALSE
            0x10C6 => { 1 }  // FindClose → TRUE
            0x10C7 => { 0xFFFF_FFFFu64 }  // GetFileAttributesW → INVALID_FILE_ATTRIBUTES
            0x10C8 | 0x10C9 | 0x10CA => { 0 }  // GetFileInformationByHandle* / SetFileInformation
            0x10CB | 0x10CC => { 0 }  // GetFullPathNameW / GetFinalPathNameByHandleW
            0x10CD => { 0 }  // CreateDirectoryW
            0x10CE => { 1 }  // SetFileCompletionNotificationModes → TRUE
            // IO completion
            0x10D0 => { 1 }  // CreateIoCompletionPort → fake handle
            0x10D1 => { 0 }  // GetQueuedCompletionStatusEx → 0
            0x10D2 => { 1 }  // PostQueuedCompletionStatus → TRUE
            // Process
            0x10E0 => { 0 }  // CreateProcessW → FALSE
            // RTL exception stubs
            0x10F0 => { 0 }  // RtlCaptureContext
            0x10F1 => { 0 }  // RtlLookupFunctionEntry → NULL (no unwind info)
            0x10F2 => { 0 }  // RtlVirtualUnwind

            // ── LocalAlloc / LocalFree (Patch 2) ─────────────────────────────
            // Thin wrappers over the existing HeapAlloc/HeapFree handlers.
            // LMEM_FIXED=0, LMEM_ZEROINIT=0x40
            0x10F3 => {
                // LocalAlloc(uFlags, uBytes) → ptr
                let bytes = arg1;
                if bytes == 0 { return 0; }
                let layout_size = bytes.max(16); // minimum 16 bytes — avoid 1-byte alloc corruption
                let ptr = crate::nt_memory::dispatch_nt_memory_syscall(0x0018, 0, layout_size, 0x3000, 0x04);
                if ptr != 0 {
                    // Always zero — physical frames may contain leftovers even after mapping
                    let pages = ((layout_size as usize + 4095) / 4096).max(1);
                    unsafe { core::ptr::write_bytes(ptr as *mut u8, 0, pages * 4096); }
                }
                ptr
            }
            0x10F4 => {
                // LocalFree(hMem) → NULL on success
                if arg0 == 0 { return 0; }
                crate::nt_memory::dispatch_nt_memory_syscall(0x001E, arg0, 0x8000, 0, 0);
                0 // NULL = success
            }
            0x10F5 => {
                // LocalReAlloc(hMem, uBytes, uFlags)
                let new_bytes = arg1.max(1);
                let new_ptr = crate::nt_memory::dispatch_nt_memory_syscall(0x0018, 0, new_bytes, 0x3000, 0x40);
                if new_ptr != 0 && arg0 != 0 {
                    // Copy old data — we don't know the old size so copy min(new,old)
                    unsafe {
                        let src = arg0 as *const u8;
                        let dst = new_ptr as *mut u8;
                        core::ptr::copy_nonoverlapping(src, dst, new_bytes as usize);
                    }
                    crate::nt_memory::dispatch_nt_memory_syscall(0x001E, arg0, 0x8000, 0, 0);
                }
                new_ptr
            }
            0x10F6 => { arg0 }  // LocalLock → return ptr (fixed memory, no locking needed)
            0x10F7 => { 1 }     // LocalUnlock → TRUE
            0x10F8 => { arg0.min(65536) } // LocalSize → stub 64KB

            // ── GetStartupInfoW (0x10F9) ─────────────────────────────────────
            // Writes a minimal STARTUPINFOW struct to the pointer in arg0.
            // Only cb (size) and dwFlags need plausible values.
            0x10F9 => {
                if arg0 > 0x1000 {
                    let ptr = arg0 as *mut u32;
                    unsafe {
                        // cb = sizeof(STARTUPINFOW) = 104 bytes (x64)
                        *ptr = 104;
                        // Zero the rest (dwFlags, wShowWindow, etc.)
                        core::ptr::write_bytes(ptr.add(1) as *mut u8, 0, 100);
                    }
                }
                0
            }

            // ── ReadFile / WriteFile (0x10FA/0x10FB) ─────────────────────────
            // Stub: WriteFile to StdOut (handle 1) echoes to serial; others fail.
            0x10FA => { 0 }  // ReadFile → FALSE (no file I/O yet)
            0x10FB => {
                // WriteFile(hFile, lpBuffer, nNumberOfBytesPerWrite, lpBytesWritten, lpOverlapped)
                let handle = arg0;
                let buf_ptr = arg1 as *const u8;
                let count   = arg2 as usize;
                if (handle == 1 || handle == 0xFFFF_FFF5) && count > 0 && buf_ptr as u64 > 0x1000 {
                    // StdOut / console — echo to serial
                    let s = unsafe { core::slice::from_raw_parts(buf_ptr, count.min(1024)) };
                    for &b in s {
                        crate::serial_print!("{}", b as char);
                    }
                    if arg3 > 0x1000 {
                        unsafe { *(arg3 as *mut u32) = count as u32; }
                    }
                    return count as u64;
                }
                0
            }

            // ── Resource helpers (0x10FC–0x10FF) ─────────────────────────────
            0x10FC => { 1 }  // FindResourceW → non-null fake handle
            0x10FD => { 1 }  // LoadResource
            0x10FE => { 1 }  // LockResource → non-null pointer
            0x10FF => { 0 }  // SizeofResource → 0

            // ── Time helpers (0x1100–0x1104) ──────────────────────────────────
            0x1100 | 0x1101 => {
                // GetLocalTime / GetSystemTime → write SYSTEMTIME to arg0
                // SYSTEMTIME: wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds
                if arg0 > 0x1000 {
                    let ptr = arg0 as *mut u16;
                    unsafe {
                        *ptr.add(0) = 2025; // wYear
                        *ptr.add(1) = 1;    // wMonth (January)
                        *ptr.add(2) = 1;    // wDayOfWeek (Monday)
                        *ptr.add(3) = 1;    // wDay
                        *ptr.add(4) = 0;    // wHour
                        *ptr.add(5) = 0;    // wMinute
                        *ptr.add(6) = 0;    // wSecond
                        *ptr.add(7) = 0;    // wMilliseconds
                    }
                }
                0
            }
            0x1102 | 0x1103 => {
                // GetDateFormatW / GetTimeFormatW → write "00:00" stub to output buffer
                if arg3 > 0x1000 && arg2 > 0 {
                    let out = arg3 as *mut u16;
                    let placeholder: &[u16] = &[b'0' as u16, b'0' as u16, b':' as u16, b'0' as u16, b'0' as u16, 0];
                    unsafe {
                        core::ptr::copy_nonoverlapping(placeholder.as_ptr(), out, placeholder.len());
                    }
                    return placeholder.len() as u64 - 1; // chars written, not counting NUL
                }
                0
            }
            0x1104 => { 0 }  // GetTimeZoneInformation → TIME_ZONE_ID_UNKNOWN
            0x1105 => {
                // GetTempPathW → write L"C:\Temp\" to buffer
                if arg1 > 0x1000 {
                    let path: &[u16] = &[b'C' as u16, b':' as u16, b'\\' as u16, b'T' as u16, b'e' as u16, b'm' as u16, b'p' as u16, b'\\' as u16, 0];
                    unsafe { core::ptr::copy_nonoverlapping(path.as_ptr(), arg1 as *mut u16, path.len()); }
                    return (path.len() - 1) as u64;
                }
                0
            }
            0x1106 => { 0 }  // GetTempFileNameW → stub
            0x1107 => { 1252 } // GetACP → Windows-1252 (Western European)
            0x1108 => { 437  } // GetOEMCP → CP437 (DOS Latin US)
            0x1109 => { 1 }    // IsValidCodePage → TRUE
            0x110A => { 0 }    // GetLocaleInfoW → empty
            0x110B => { 0x0409 } // GetUserDefaultLCID / GetSystemDefaultLCID → en-US
            0x110C => { 1 }    // SetStdHandle → TRUE
            0x110D => { 1 }    // FlushFileBuffers → TRUE
            0x110E => { 1 }    // SetEndOfFile → TRUE
            0x110F => {
                // GetFileSizeEx(hFile, lpFileSize) → write 0 to LARGE_INTEGER
                if arg1 > 0x1000 { unsafe { *(arg1 as *mut u64) = 0; } }
                1
            }
            0x1110 => { 1 }    // SetFilePointerEx → TRUE

            // ── Synch extras ─────────────────────────────────────────────────

            // ── Threadpool API (0x1111–0x111D) ──────────────────────────────
            // Each Create* returns a pointer to a fresh zeroed page so that
            // callers can safely read/write fields in the returned "object"
            // without faulting.  We share a single bump allocator region
            // (0xB_0000_0000) for all threadpool objects.
            0x1111 => {
                // CreateThreadpoolTimer(pfnti, pv, pcbe) → PTP_TIMER
                // Allocate 64 bytes (one cache line, covers [ptr+0x38]) zeroed.
                tpool_alloc()
            }
            0x1112 => { 0 }  // SetThreadpoolTimer — no-op
            0x1113 => { 0 }  // CloseThreadpoolTimer — no-op
            0x1114 => { 0 }  // WaitForThreadpoolTimerCallbacks — no-op
            0x1115 => {
                // CreateThreadpoolWork(pfnwk, pv, pcbe) → PTP_WORK
                tpool_alloc()
            }
            0x1116 => { 0 }  // SubmitThreadpoolWork — no-op
            0x1117 => { 0 }  // CloseThreadpoolWork — no-op
            0x1118 => {
                // CreateThreadpoolIo(fl, pfnio, pv, pcbe) → PTP_IO
                tpool_alloc()
            }
            0x1119 => { 0 }  // CloseThreadpoolIo — no-op
            0x111A => {
                // CreateThreadpool(reserved) → PTP_POOL
                tpool_alloc()
            }
            0x111B => { 0 }  // CloseThreadpool — no-op
            0x111C => {
                // InitializeThreadpoolEnvironment(pcbe) — zero the struct in-place
                if arg0 > 0x1000 {
                    unsafe { core::ptr::write_bytes(arg0 as *mut u8, 0, 64); }
                }
                0
            }
            0x111D => { 0 }  // SetThreadpoolCallbackPool — no-op

            // ── user32.dll stubs ─────────────────────────────────────────────
            // MessageBoxA/W (0x2001)
            0x2001 => { println!("[USER32] MessageBoxA hwnd={}", arg0); 1 }

            // CreateWindowExA/W (0x2002)
            // After the ABI fix: arg0=dwExStyle, arg1=lpClassName, arg2=lpWindowName, arg3=dwStyle
            // x/y/w/h are stack args 4–7, read via interrupts::syscall_stack_arg().
            // (falls back to 100,100 / 800×600 for CW_USEDEFAULT).
            0x2002 => win32_user::dispatch_win32_user_syscall(0x4001, arg0, arg1, arg2, arg3),

            // ShowWindow (0x2003): arg0=hwnd, arg1=nCmdShow
            // BUG WAS: mapped to 0x4002 (DestroyWindow) — fixed to 0x4003 (ShowWindow)
            0x2003 => win32_user::dispatch_win32_user_syscall(0x4003, arg0, arg1, 0, 0),

            // UpdateWindow (0x2004): forces a synchronous WM_PAINT — stub success
            0x2004 => { 1 }

            // DispatchMessageA/W (0x2005): decode MSG struct and handle key messages.
            // arg0 = pointer to MSG struct { hwnd:u32, message:u32, wParam:u64, lParam:u64, time:u32, ptX:i32, ptY:i32 }
            // Layout (x64 packed): hwnd@0(4), message@4(4), wParam@8(8), lParam@16(8), time@24(4), ptX@28(4), ptY@32(4)
            0x2005 => {
                if arg0 > 0x1000 {
                    let base = arg0 as *const u8;
                    let (hwnd, message, wparam, lparam) = unsafe {
                        let hwnd    = *(base.add(0x00) as *const u64) as u32;
                        let message = *(base.add(0x08) as *const u32);
                        let wparam  = *(base.add(0x10) as *const u64);
                        let lparam  = *(base.add(0x18) as *const u64);
                        (hwnd, message, wparam, lparam)
                    };
                    if crate::interrupts::syscall_trace() {
                        crate::serial_println!("[DISPATCH] hwnd={} msg={:#X} wp={:#X} lp={:#X}", hwnd, message, wparam, lparam);
                    }
                    match message {
                        crate::win32_user::WM_PAINT => {
                            // Trigger a compositor repaint for this window.
                            // Read the surface id first (drop the lock), then
                            // query size and mark dirty in a second lock scope
                            // to avoid a double-borrow on COMPOSITOR.
                            let _sid_and_dims = {
                                let mut comp = crate::compositor::COMPOSITOR.lock();
                                let sid = crate::loader::lock_guard::lock_tracked(&crate::win32_user::WIN32_USER)
                                    .find_window(hwnd)
                                    .map(|w| w.user_data as crate::compositor::SurfaceId)
                                    .unwrap_or(0);
                                if sid != 0 {
                                    comp.surface_mut(sid)
                                        .map(|s| (sid, s.width, s.height))
                                } else {
                                    None
                                }
                            };
                            // Surface marked dirty implicitly — timer ISR will repaint
                            // on the next 60fps frame via wm.repaint_all()
                            0
                        }
                        crate::win32_user::WM_DESTROY => {
                            // Post WM_QUIT to the thread that owns this window,
                            // not the hardcoded tid=1 which broke multi-window apps.
                            let owning_tid = crate::loader::lock_guard::lock_tracked(&crate::win32_user::WIN32_USER)
                                .find_window(hwnd)
                                .map(|w| w.owning_tid)
                                .unwrap_or(1);
                            crate::loader::lock_guard::lock_tracked(&crate::win32_user::WIN32_USER).post_quit(owning_tid, 0);
                            0
                        }
                        crate::win32_user::WM_CLOSE => {
                            // Default: destroy the window.
                            // Call destroy_window() directly rather than going through
                            // dispatch_win32_user_syscall(0x4002) which would deadlock
                            // if WIN32_USER is already locked in an outer call frame.
                            crate::loader::lock_guard::lock_tracked(&crate::win32_user::WIN32_USER).destroy_window(hwnd);
                            0
                        }
                        crate::win32_user::WM_SIZE => {
                            // Resize the compositor surface
                            let new_w = (lparam & 0xFFFF) as u32;
                            let new_h = ((lparam >> 16) & 0xFFFF) as u32;
                            if new_w > 0 && new_h > 0 {
                                let sid = crate::loader::lock_guard::lock_tracked(&crate::win32_user::WIN32_USER)
                                    .find_window(hwnd)
                                    .map(|w| w.user_data as crate::compositor::SurfaceId)
                                    .unwrap_or(0);
                                if sid != 0 {
                                    crate::compositor::COMPOSITOR.lock().resize_surface(sid, new_w, new_h);
                                }
                            }
                            0
                        }
                        _ => 0,  // All other messages: default proc returns 0
                    }
                } else {
                    0
                }
            }

            // TranslateMessage (0x2006): translates WM_KEYDOWN → WM_CHAR — stub success
            // BUG WAS: mapped to 0x4007 (PostQuitMessage!) — fixed
            0x2006 => { 1 }

            // PostQuitMessage (0x2007): arg0=exit_code
            // BUG WAS: mapped to 0x4009 (GetMessage) — fixed to 0x4007 (PostQuitMessage)
            0x2007 => win32_user::dispatch_win32_user_syscall(0x4007, arg0, 0, 0, 0),

            // PeekMessageA/W (0x2008): arg0=hwnd_filter, arg1=msg_min, arg2=pm_flags
            // BUG WAS: mapped to 0x400A (SetTimer) — fixed to 0x4008 (PeekMessage)
            0x2008 => win32_user::dispatch_win32_user_syscall(0x4008, arg0, arg1, arg2, 0),

            // RegisterClassExA/W (0x200A), RegisterClassA/W (0x200B)
            // arg0 = pointer to WNDCLASSW / WNDCLASSEXW struct
            //
            // WNDCLASSW layout (x64):
            //   0x00: style (u32)    0x04: pad
            //   0x08: lpfnWndProc    0x10: cbClsExtra (i32)
            //   0x14: cbWndExtra     0x18: hInstance
            //   0x20: hIcon          0x28: hCursor
            //   0x30: hbrBackground  0x38: lpszMenuName
            //   0x40: lpszClassName
            //
            // WNDCLASSEXW layout (x64):  same but starts with cbSize (u32)
            //   at +0x00, shifting everything else by 4+4 pad = +8 bytes.
            //   So lpfnWndProc is at 0x08 for WNDCLASS, 0x10 for WNDCLASSEX.
            0x200A | 0x200B => {
                let mut wnd_proc: u64 = 0;
                let mut class_name_str = alloc::string::String::from("Win32Class");

                if arg0 > 0x1000 {
                    let base = arg0 as *const u8;
                    // Detect WNDCLASSEX vs WNDCLASS:
                    // 0x200A = RegisterClassEx, 0x200B = RegisterClass
                    let proc_offset: usize = if id == 0x200A { 0x10 } else { 0x08 };
                    let classname_offset: usize = if id == 0x200A { 0x48 } else { 0x40 };

                    unsafe {
                        wnd_proc = *(base.add(proc_offset) as *const u64);

                        // Read class name as wide string (null-terminated UTF-16)
                        let name_ptr = *(base.add(classname_offset) as *const u64);
                        if name_ptr > 0x1000 {
                            let wstr = name_ptr as *const u16;
                            let mut s = alloc::string::String::new();
                            for i in 0..128 {
                                let ch = *wstr.add(i);
                                if ch == 0 { break; }
                                s.push(char::from_u32(ch as u32).unwrap_or('?'));
                            }
                            if !s.is_empty() { class_name_str = s; }
                        }
                    }
                }

                crate::serial_println!(
                    "[USER32] RegisterClass '{}' wndproc={:#X} -> atom 0xC0DE",
                    class_name_str, wnd_proc
                );

                // Store the class registration so CreateWindow can look up the wndproc
                crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER).class_entries.push(
                    win32_user::ClassEntry {
                        class_name: class_name_str,
                        wnd_proc,
                        style: 0,
                    }
                );

                0xC0DE
            }

            // GetMessageA/W (0x200C): blocking message wait — forward to internal GetMessage
            0x200C => win32_user::dispatch_win32_user_syscall(0x4009, arg0, arg1, arg2, 0),

            // DefWindowProcA/W (0x200D): default window procedure.
            // arg0=hwnd, arg1=msg, arg2=wParam, arg3=lParam
            // On real Windows the most important default is:
            //   WM_CLOSE  → DestroyWindow(hwnd)
            //   WM_DESTROY→ (no-op at this level; app calls PostQuitMessage itself)
            // Everything else returns 0.
            0x200D => {
                let hwnd = arg0 as u32;
                let msg  = arg1 as u32;
                match msg {
                    crate::win32_user::WM_CLOSE => {
                        // Default close: destroy the window.
                        crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER).destroy_window(hwnd);
                        0
                    }
                    _ => 0,
                }
            }

            // BeginPaint (0x200E): arg0=hwnd, arg1=PAINTSTRUCT*
            // Allocates a real HDC so subsequent GDI calls (TextOut, FillRect, etc.)
            // can resolve the surface via dc_surface() and actually draw.
            0x200E => {
                // Delegate to GetDC(hwnd) — returns a real allocated GDI DC handle.
                let hdc = win32_user::dispatch_win32_user_syscall(0x400C, arg0, 0, 0, 0);
                // If caller provided a PAINTSTRUCT pointer, write the HDC into it
                // (hdc is the first field at offset 0).
                if arg1 > 0x1000 {
                    unsafe { *(arg1 as *mut u64) = hdc; }
                }
                hdc
            }

            // EndPaint (0x200F): arg0=hwnd, arg1=PAINTSTRUCT*  — release the HDC
            0x200F => {
                // Read hdc from PAINTSTRUCT (field 0) and release it.
                if arg1 > 0x1000 {
                    let hdc = unsafe { *(arg1 as *const u64) };
                    if hdc > 0 && hdc != 0x0DC0_FFEE {
                        win32_user::dispatch_win32_user_syscall(0x400D, arg0, hdc, 0, 0);
                    }
                }
                1
            }

            // LoadCursorA/W (0x2011), LoadIconA/W (0x2012): return stub handles
            0x2011 => { 0x0001 }
            0x2012 => { 0x0001 }

            // GetClientRect (0x2013): arg0=hwnd, arg1=RECT*
            // Writes the client area RECT for the window (left=0, top=0, right=w, bottom=h).
            0x2013 => {
                if arg1 > 0x1000 {
                    let (w, h) = crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER)
                        .find_window(arg0 as u32)
                        .map(|w| (w.w, w.h))
                        .unwrap_or((800, 600));
                    let rect = arg1 as *mut i32;
                    unsafe {
                        *rect.add(0) = 0;
                        *rect.add(1) = 0;
                        *rect.add(2) = w as i32;
                        *rect.add(3) = h as i32;
                    }
                }
                1
            }

            // InvalidateRect (0x2014)
            0x2014 => { 1 }

            // SetWindowLongPtrA/W (0x2017), GetWindowLongPtrA/W (0x2018)
            0x2017 => { 0 }
            0x2018 => { 0 }

            // GetSystemMetrics (0x201A): return common defaults
            0x201A => {
                match arg0 {
                    0  => 1920, // SM_CXSCREEN
                    1  => 1080, // SM_CYSCREEN
                    _  => 0,
                }
            }

            // AdjustWindowRectEx (0x201B)
            0x201B => { 1 }

            // SetFocus / GetForegroundWindow (0x201C, 0x201D)
            0x201C | 0x201D => { 0 }

            // ---- GDI32 Subsystem (0x4001–0x402B) ----
            // Existing symbols (0x4001–0x4008) kept, new ones added.

            // GetStockObject(nIndex) → fake handle per object type
            0x4001 => {
                match arg0 {
                    0  => 0x8001, // WHITE_BRUSH
                    1  => 0x8002, // LTGRAY_BRUSH
                    4  => 0x8003, // BLACK_BRUSH
                    5  => 0x8004, // NULL_BRUSH / HOLLOW_BRUSH
                    6  => 0x8005, // WHITE_PEN
                    7  => 0x8006, // BLACK_PEN
                    8  => 0x8007, // NULL_PEN
                    17 => 0x8008, // SYSTEM_FONT
                    _  => 0x8009,
                }
            }
            // BitBlt — forward to win32_user
            0x4002 => win32_user::dispatch_win32_user_syscall(0x401A, arg0, arg1, arg2, arg3),
            // CreateCompatibleDC
            0x4003 => win32_user::dispatch_win32_user_syscall(0x400E, arg0, 0, 0, 0),
            // DeleteDC
            0x4004 => win32_user::dispatch_win32_user_syscall(0x400F, arg0, 0, 0, 0),
            // SelectObject
            0x4005 => win32_user::dispatch_win32_user_syscall(0x4013, arg0, arg1, 0, 0),
            // GetDeviceCaps(hdc, nIndex) — return plausible display values
            0x4006 => {
                match arg1 {
                    2  => 96,    // HORZRES (logical width px) — use 96 DPI default
                    4  => 96,    // VERTRES
                    8  => 96,    // HORZSIZE (mm) — approximate
                    10 => 96,
                    12 => 96,    // BITSPIXEL
                    88 => 1920,  // DESKTOPHORZRES
                    90 => 1080,  // DESKTOPVERTRES
                    _  => 96,
                }
            }
            // DeleteObject
            0x4007 => win32_user::dispatch_win32_user_syscall(0x4012, arg0, 0, 0, 0),
            // CreateSolidBrush
            0x4008 => win32_user::dispatch_win32_user_syscall(0x4010, arg0, 0, 0, 0),

            // ── New GDI32 stubs (Patch 4) ────────────────────────────────────

            // CreateFontIndirectW/A (0x4009) — return a fake HFONT
            0x4009 => {
                let hfont = crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER).gdi_object_count() as u64 + 0xF000;
                hfont
            }
            // CreateFontW/A (0x400A) — same stub
            0x400A => {
                let hfont = crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER).gdi_object_count() as u64 + 0xF100;
                hfont
            }
            // GetTextMetricsW/A (0x400B) — write a plausible TEXTMETRIC struct
            // Only the first few fields matter for most apps; we set height=16, avgWidth=8.
            0x400B => {
                if arg1 > 0x1000 {
                    let ptr = arg1 as *mut i32;
                    unsafe {
                        *ptr.add(0)  = 16; // tmHeight
                        *ptr.add(1)  = 12; // tmAscent
                        *ptr.add(2)  = 4;  // tmDescent
                        *ptr.add(3)  = 0;  // tmInternalLeading
                        *ptr.add(4)  = 0;  // tmExternalLeading
                        *ptr.add(5)  = 8;  // tmAveCharWidth
                        *ptr.add(6)  = 16; // tmMaxCharWidth
                        *ptr.add(7)  = 400; // tmWeight (FW_NORMAL)
                        *ptr.add(8)  = 0;  // tmOverhang
                        *ptr.add(9)  = 96; // tmDigitizedAspectX
                        *ptr.add(10) = 96; // tmDigitizedAspectY
                        // Rest zeroed (tmFirstChar, tmLastChar, etc.)
                        core::ptr::write_bytes(ptr.add(11) as *mut u8, 0, 16);
                    }
                }
                1 // TRUE
            }
            // TextOutW/A (0x400C) — forward to win32_user TextOutA
            // arg0=hdc, arg1=x, arg2=y, arg3=lpString (pointer into user-mode)
            0x400C => {
                let text: alloc::string::String = if arg3 > 0x1000 {
                    let ptr = arg3 as *const u16;
                    let mut s = alloc::string::String::new();
                    for i in 0..512usize {
                        let ch = unsafe { *ptr.add(i) };
                        if ch == 0 { break; }
                        s.push(char::from_u32(ch as u32).unwrap_or('?'));
                    }
                    s
                } else { alloc::string::String::new() };
                let state = crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER);
                state.text_out_a(arg0 as u32, arg1 as i32, arg2 as i32, &text) as u64
            }
            // GetTextExtentPoint32W/A (0x400D)
            // arg0=hdc, arg1=lpString, arg2=c (char count), arg3=lpSize (LPSIZE)
            // Write approximate SIZE{w,h} based on 8×16 monospace glyph.
            0x400D => {
                let char_count = arg2 as i32;
                if arg3 > 0x1000 {
                    let ptr = arg3 as *mut i32;
                    unsafe {
                        *ptr.add(0) = char_count * 8;  // cx (width)
                        *ptr.add(1) = 16;               // cy (height)
                    }
                }
                1 // TRUE
            }
            // SetBkMode (0x400E) — return previous mode (stub: OPAQUE=2)
            0x400E => { 2 }
            // SetMapMode (0x400F) — return previous mode (MM_TEXT=1)
            0x400F => { 1 }
            // SetTextColor (0x4010) — return previous color (stub: black)
            0x4010 => { 0x000000 }
            // SetBkColor (0x4011) — return previous bk color (stub: white)
            0x4011 => { 0xFFFFFF }
            // GetTextColor (0x4012) — return current text color (stub: black)
            0x4012 => { 0x000000 }
            // CreateCompatibleBitmap (0x4013) — return a fake HBITMAP
            0x4013 => {
                let hbmp = crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER).gdi_object_count() as u64 + 0xB000;
                hbmp
            }
            // GetObjectW/A (0x4014) — write a BITMAP/LOGFONT stub
            0x4014 => {
                if arg2 > 0x1000 && arg1 > 0 {
                    unsafe { core::ptr::write_bytes(arg2 as *mut u8, 0, arg1 as usize); }
                }
                arg1 // return bytes filled
            }
            // CreatePen (0x4015) — forward
            0x4015 => win32_user::dispatch_win32_user_syscall(0x4011, arg0, arg1, arg2, 0),
            // MoveToEx (0x4016) — forward
            0x4016 => win32_user::dispatch_win32_user_syscall(0x4014, arg0, arg1, arg2, 0),
            // LineTo (0x4017) — forward
            0x4017 => win32_user::dispatch_win32_user_syscall(0x4015, arg0, arg1, arg2, 0),
            // Rectangle (0x4018) — forward
            0x4018 => win32_user::dispatch_win32_user_syscall(0x4016, arg0, arg1, arg2, arg3),
            // Ellipse (0x4019) — forward
            0x4019 => win32_user::dispatch_win32_user_syscall(0x4017, arg0, arg1, arg2, arg3),
            // FillRect (0x401A) — forward
            0x401A => win32_user::dispatch_win32_user_syscall(0x4019, arg0, arg1, arg2, arg3),
            // DrawTextW/A (0x401B) — call TextOut at (x=arg2.left, y=arg2.top)
            0x401B => {
                // arg0=hdc, arg1=lpchText, arg2=cchText, arg3=lprc (RECT*), (nFormat on stack - inaccessible)
                // Read left/top from RECT
                let (rx, ry) = if arg3 > 0x1000 {
                    unsafe { (*(arg3 as *const i32), *(arg3 as *const i32).add(1)) }
                } else { (0, 0) };
                let text: alloc::string::String = if arg1 > 0x1000 {
                    let ptr = arg1 as *const u16;
                    let count = if arg2 as i32 == -1 { 256 } else { (arg2 as usize).min(512) };
                    let mut s = alloc::string::String::new();
                    for i in 0..count {
                        let ch = unsafe { *ptr.add(i) };
                        if ch == 0 { break; }
                        s.push(char::from_u32(ch as u32).unwrap_or('?'));
                    }
                    s
                } else { alloc::string::String::new() };
                let height = text.lines().count().max(1) as i32 * 16;
                let state = crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER);
                state.text_out_a(arg0 as u32, rx, ry, &text);
                height as u64
            }
            // SetStretchBltMode (0x401C) — return previous mode
            0x401C => { 1 }
            // StretchBlt (0x401D) — stub success
            0x401D => { 1 }
            // PatBlt (0x401E) — stub success
            0x401E => { 1 }
            // GetDC / ReleaseDC gdi32 aliases (0x401F–0x4020)
            0x401F => win32_user::dispatch_win32_user_syscall(0x400C, arg0, 0, 0, 0),
            0x4020 => win32_user::dispatch_win32_user_syscall(0x400D, arg0, arg1, 0, 0),
            // SaveDC (0x4021) — return fake save state 1
            0x4021 => { 1 }
            // RestoreDC (0x4022) — TRUE
            0x4022 => { 1 }
            // SetViewportOrgEx / SetWindowOrgEx (0x4023–0x4024)
            0x4023 | 0x4024 => { 1 }
            // ExcludeClipRect / IntersectClipRect (0x4025–0x4026)
            0x4025 | 0x4026 => { 1 } // SIMPLEREGION
            // GetClipBox (0x4027) — write full-window RECT
            0x4027 => {
                if arg1 > 0x1000 {
                    let r = arg1 as *mut i32;
                    unsafe { *r = 0; *r.add(1) = 0; *r.add(2) = 1920; *r.add(3) = 1080; }
                }
                1
            }
            // CreateDIBSection (0x4028) — allocate backing memory, return fake HBITMAP
            0x4028 => {
                // arg2=BITMAPINFO*, arg3=iUsage, (ppvBits on stack)
                // We can't easily return ppvBits through our 4-arg ABI, so return a fake handle.
                let hbmp = crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER).gdi_object_count() as u64 + 0xD000;
                hbmp
            }
            // SetDIBitsToDevice (0x4029) — stub success
            0x4029 => { 1 }
            // GdiFlush (0x402A) — TRUE (all ops are synchronous)
            0x402A => { 1 }
            // GetSystemMetrics gdi32 alias (0x402B)
            0x402B => {
                match arg0 { 0 => 1920, 1 => 1080, _ => 0 }
            }
            
            // ---- OpenGL32 Subsystem (0x5000) ----
            0x5004 => 0, // glGetError: GL_NO_ERROR
            
            // ---- Shell32 Subsystem (0x6000) ----
            0x6001 => { println!("[SHELL32] ShellExecute: {}", arg0); 33 }
            
            // ---- Ole32 Subsystem (0x7000) ----
            0x7001 => { println!("[OLE32] CoInitialize"); 0 }
            
            // ---- WS2_32 Subsystem (0x8000) ----
            0x8001 => { println!("[WS2_32] WSAStartup"); 0 }

            // ---- Universal C Runtime (0x9000) ----
            0x9001 => {
                // malloc(size)
                let size = arg0 as usize;
                if size == 0 { return 0; }
                let mut mapper = unsafe { crate::memory::get_mapper() };
                let mut fa     = crate::memory::GlobalFrameAllocator;

                let num_pages = core::cmp::max((size + 4095) / 4096, 1);
                static MALLOC_PTR: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0x8_0000_0000);
                let addr = MALLOC_PTR.fetch_add(
                    (num_pages as u64 * 4096) + 4096,
                    core::sync::atomic::Ordering::Relaxed,
                );

                for i in 0..num_pages {
                    let page = x86_64::structures::paging::Page::containing_address(
                        x86_64::VirtAddr::new(addr + (i as u64 * 4096)));
                    let frame = match crate::memory::allocate_frame() {
                        Some(f) => f,
                        None    => return 0, // OOM
                    };
                    crate::memory::map_page(page, frame,
                        x86_64::structures::paging::PageTableFlags::PRESENT |
                        x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE |
                        x86_64::structures::paging::PageTableFlags::WRITABLE,
                        &mut mapper, &mut fa);
                }
                // Register so free() can unmap the correct number of pages.
                crt_track_alloc(addr, num_pages);
                addr
            }
            0x9002 => {
                // free(ptr) — unmap pages and scrub memory to prevent leaks.
                // crt_free() looks up the page count from the tracker, zeros
                // each page, then removes the PTEs and flushes the TLB.
                // Returns 0 (void in C) regardless of whether the pointer was
                // a valid tracked allocation (mirrors C free() semantics).
                if arg0 != 0 {
                    crt_free(arg0);
                }
                0
            }
            0x9003 => {
                // calloc(count, size) — allocate zeroed memory
                let count = arg0 as usize;
                let elem_size = arg1 as usize;
                let total = count.saturating_mul(elem_size);
                if total == 0 { return 0; }
                let mut mapper = unsafe { crate::memory::get_mapper() };
                let mut fa     = crate::memory::GlobalFrameAllocator;
                let num_pages = core::cmp::max((total + 4095) / 4096, 1);
                static CALLOC_PTR: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0x8_8000_0000);
                let addr = CALLOC_PTR.fetch_add(
                    (num_pages as u64 * 4096) + 4096,
                    core::sync::atomic::Ordering::Relaxed,
                );
                for i in 0..num_pages {
                    let page = x86_64::structures::paging::Page::containing_address(
                        x86_64::VirtAddr::new(addr + (i as u64 * 4096)));
                    let frame = match crate::memory::allocate_frame() {
                        Some(f) => f,
                        None    => return 0,
                    };
                    crate::memory::map_page(page, frame,
                        x86_64::structures::paging::PageTableFlags::PRESENT |
                        x86_64::structures::paging::PageTableFlags::USER_ACCESSIBLE |
                        x86_64::structures::paging::PageTableFlags::WRITABLE,
                        &mut mapper, &mut fa);
                }
                // calloc guarantees zero-initialised memory.
                unsafe { core::ptr::write_bytes(addr as *mut u8, 0, num_pages * 4096); }
                // Register for free().
                crt_track_alloc(addr, num_pages);
                addr
            }
            
            0x9301 => {
                // memset(dest, value, size)
                let dest = arg0 as *mut u8;
                let val  = arg1 as u8;
                let len  = arg2 as usize;
                unsafe { core::ptr::write_bytes(dest, val, len); }
                arg0
            }
            0x9302 => {
                // memcpy(dest, src, size)
                let dest = arg0 as *mut u8;
                let src  = arg1 as *const u8;
                let len  = arg2 as usize;
                if len > 0 && dest as u64 > 0x1000 && src as u64 > 0x1000 {
                    unsafe { core::ptr::copy_nonoverlapping(src, dest, len); }
                }
                arg0
            }
            0x9303 => {
                // memmove(dest, src, size) — handles overlapping regions
                let dest = arg0 as *mut u8;
                let src  = arg1 as *const u8;
                let len  = arg2 as usize;
                if len > 0 && dest as u64 > 0x1000 && src as u64 > 0x1000 {
                    unsafe { core::ptr::copy(src, dest, len); }
                }
                arg0
            }
            
            0x9101 | 0x9102 => {
                // _initterm / _initterm_e — fallback if reached via syscall
                // (Should be intercepted at IAT link time and redirected to
                // user-mode code, but handle gracefully if not.)
                crate::serial_println!("[CRT] _initterm syscall fallback (should be user-mode)");
                0
            }
            
            // ---- Bcrypt primitives (0xA000) ----
            0xA001 => {
                // ProcessPrng(buffer, size)
                let buf = arg0 as *mut u8;
                let len = arg1 as usize;
                for i in 0..len {
                    unsafe { *buf.add(i) = (crate::interrupts::TICKS.load(core::sync::atomic::Ordering::Relaxed) & 0xFF) as u8; }
                }
                1 
            }

            // ---- DWM / UXTheme / IMM32 (0xC000+) ----
            0xC001 => 1, // DwmIsCompositionEnabled = true
            0xC002 | 0xC003 => 0, // DwmSetWindowAttribute / ExtendFrame
            
            0xD001 => 0, // SetWindowTheme
            0xD002 => 1, // IsAppThemed = true
            
            0xE001 => 0xCAFE, // ImmGetContext handle
            0xE002 => 1,      // ImmReleaseContext
            
            // ---- UI Automation (0xF000) ----
            0xF001 => 1, // UiaLookupId
            0xF002 => 0,

            // ---- Expanded Synchronization (SRW / CV) ----
            // SRW Locks — InitializeSRWLock zeros the SRWLOCK in-place (it's just a PVOID)
            0x1026 => {
                // InitializeSRWLock(SRWLOCK*) — zero the lock word
                if arg0 > 0x1000 { unsafe { *(arg0 as *mut u64) = 0; } }
                0
            }
            0x1027 | 0x1029 => { 0 }  // Acquire SRW Exclusive/Shared — always succeed (single-threaded)
            0x1028 | 0x102A => { 0 }  // Release SRW Exclusive/Shared
            0x102B | 0x102C => { 1 }  // TryAcquireSRW* — always return TRUE (lock available)
            // Condition variables
            0x102D | 0x102E => { 0 }  // Wake/WakeAll ConditionVariable — no-op
            0x102F => { 1 }           // InitOnceBeginInitialize — return TRUE (first time)
            0x1120 => { 1 }           // InitOnceComplete — always OK
            // WakeByAddress
            0x10BF => { 0 }           // WakeByAddressSingle
            0x1121 => { 0 }           // WakeByAddressAll

            // ---- CRT Math (0x9500) ----
            //
            // We implement software approximations so that:
            //   • No divide-by-zero occurs when results are used as divisors
            //     (sin→0 was the main culprit — passing the input through
            //     avoids a hard zero while staying plausible for small angles)
            //   • sqrt() never returns 0 for positive inputs (breaks code
            //     that divides by sqrt(x))
            //
            // All functions receive their f64 argument in arg0 as raw bits and
            // return f64 result bits in the return value (standard VEILOS CRT ABI).
            //
            // sin(x) ≈ x for |x| << 1 (common in game math). For larger inputs
            // we at least preserve the sign and avoid a hard 0.
            0x9501 => {  // sin(x) — Bhaskara I approximation (good to ~0.1% for 0..π)
                let x = f64::from_bits(arg0);
                if !x.is_finite() { return arg0; } // propagate NaN/Inf unchanged
                // Reduce to [-π, π] with a simple modulo approximation.
                const TWO_PI: f64 = 6.283185307179586;
                let xr = x - TWO_PI * libm_round(x / TWO_PI);
                // Bhaskara I: sin(x) ≈ 16x(π-x) / (5π²-4x(π-x)) for x in [0,π]
                let sin_val = bhaskara_sin(xr);
                sin_val.to_bits()
            }
            0x9502 => {  // cos(x) = sin(x + π/2)
                let x = f64::from_bits(arg0);
                if !x.is_finite() { return arg0; }
                const HALF_PI: f64 = 1.5707963267948966;
                const TWO_PI:  f64 = 6.283185307179586;
                let shifted = {
                    let xr = (x + HALF_PI) - TWO_PI * libm_round((x + HALF_PI) / TWO_PI);
                    bhaskara_sin(xr)
                };
                shifted.to_bits()
            }
            0x9503 => {  // tan(x) = sin(x)/cos(x) — return sin(x) if cos near 0 to avoid /0
                let x = f64::from_bits(arg0);
                if !x.is_finite() { return arg0; }
                const TWO_PI:  f64 = 6.283185307179586;
                const HALF_PI: f64 = 1.5707963267948966;
                let xr = x - TWO_PI * libm_round(x / TWO_PI);
                let s = bhaskara_sin(xr);
                let c = bhaskara_sin(xr + HALF_PI - TWO_PI * libm_round((xr + HALF_PI) / TWO_PI));
                let tan_val = if c.abs() < 1e-10 { s } else { s / c };
                tan_val.to_bits()
            }
            0x9504 => {  // sqrt(x) — software Newton-Raphson (3 iterations, ~14 sig bits)
                let x = f64::from_bits(arg0);
                if x < 0.0 || x.is_nan() { return f64::NAN.to_bits(); }
                if x == 0.0              { return 0u64; }
                if !x.is_finite()        { return arg0; } // +Inf → +Inf
                software_sqrt(x).to_bits()
            }
            0x9505 => {  // ceil(x) — pass through with integer rounding
                let x = f64::from_bits(arg0);
                if !x.is_finite() || x == 0.0 { return arg0; }
                let truncated = x as i64 as f64;
                let result = if truncated < x { truncated + 1.0 } else { truncated };
                result.to_bits()
            }
            0x9506 => {  // floor(x)
                let x = f64::from_bits(arg0);
                if !x.is_finite() || x == 0.0 { return arg0; }
                let truncated = x as i64 as f64;
                let result = if truncated > x { truncated - 1.0 } else { truncated };
                result.to_bits()
            }
            0x9507 => {  // pow(base, exp) — integer-exp fast path + fallback to exp(n·ln(b))
                let base = f64::from_bits(arg0);
                let exp  = f64::from_bits(arg1);
                if !base.is_finite() || !exp.is_finite() { return arg0; }
                if exp == 0.0 { return (1.0f64).to_bits(); }
                if base == 0.0 { return 0u64; }
                if base == 1.0 { return (1.0f64).to_bits(); }
                // Integer exponent: repeated squaring
                let exp_i = exp as i64;
                if exp_i as f64 == exp && exp_i.abs() < 64 {
                    let mut result = 1.0f64;
                    let mut base_p = if exp_i < 0 { 1.0 / base } else { base };
                    let mut n = exp_i.unsigned_abs();
                    while n > 0 {
                        if n & 1 != 0 { result *= base_p; }
                        base_p *= base_p;
                        n >>= 1;
                    }
                    result.to_bits()
                } else {
                    // Non-integer exponent: exp(exp * ln(base)) via software ln + exp.
                    if base < 0.0 {
                        // Negative base with non-integer exponent → NaN in IEEE 754.
                        return f64::NAN.to_bits();
                    }
                    let ln_base = software_ln(base.max(f64::MIN_POSITIVE));
                    software_exp(exp * ln_base).to_bits()
                }
            }

            // f64 exp / log family (0x9517–0x951A)
            // These IDs are the double-precision counterparts of the f32
            // variants above.  Argument in arg0 as raw f64 bits; result
            // returned as raw f64 bits — same ABI as 0x9501–0x9507.
            0x9517 => {  // exp(x) — e^x
                let x = f64::from_bits(arg0);
                if !x.is_finite() { return arg0; }
                software_exp(x).to_bits()
            }
            0x9518 => {  // log(x) — natural logarithm
                let x = f64::from_bits(arg0);
                if x <= 0.0 { return f64::NAN.to_bits(); }
                if !x.is_finite() { return arg0; }
                software_ln(x).to_bits()
            }
            0x9519 => {  // log2(x)
                let x = f64::from_bits(arg0);
                if x <= 0.0 { return f64::NAN.to_bits(); }
                if !x.is_finite() { return arg0; }
                (software_ln(x) / core::f64::consts::LN_2).to_bits()
            }
            0x951A => {  // log10(x)
                let x = f64::from_bits(arg0);
                if x <= 0.0 { return f64::NAN.to_bits(); }
                if !x.is_finite() { return arg0; }
                const LN10: f64 = 2.302585092994046;
                (software_ln(x) / LN10).to_bits()
            }
            0x951B => {  // fabs(x)
                let x = f64::from_bits(arg0);
                x.abs().to_bits()
            }
            0x951C => {  // round(x) — round half away from zero
                let x = f64::from_bits(arg0);
                if !x.is_finite() { return arg0; }
                let r = if x >= 0.0 { (x + 0.5) as i64 as f64 }
                        else        { (x - 0.5) as i64 as f64 };
                r.to_bits()
            }
            0x951D => {  // fmod(x, y)
                let x = f64::from_bits(arg0);
                let y = f64::from_bits(arg1);
                if y == 0.0 { return f64::NAN.to_bits(); }
                let q = x / y;
                let truncated = if q >= 0.0 { q as i64 as f64 } else { (q + 1.0) as i64 as f64 - 1.0 };
                (x - truncated * y).to_bits()
            }
            0x951E => {  // trunc(x)
                let x = f64::from_bits(arg0);
                if !x.is_finite() { return arg0; }
                (x as i64 as f64).to_bits()
            }

            // ---- CRT Locale (0x9600) ----
            0x9601 => 0, // _configthreadlocale success
            0x9602 => 65001, // ___lc_codepage_func → UTF-8 codepage

            // ── user32 new symbols ──────────────────────────────────────────
            0x201E => win32_user::dispatch_win32_user_syscall(0x400A, arg0, arg1, arg2, arg3), // SetTimer
            0x201F => win32_user::dispatch_win32_user_syscall(0x400B, arg0, arg1, 0, 0),       // KillTimer
            0x2020 => win32_user::dispatch_win32_user_syscall(0x400C, arg0, 0, 0, 0),          // GetDC
            0x2021 => win32_user::dispatch_win32_user_syscall(0x400D, arg0, arg1, 0, 0),       // ReleaseDC
            // GetWindowRect (0x2022): arg0=hwnd, arg1=RECT*
            0x2022 => {
                if arg1 > 0x1000 {
                    let (x, y, w, h) = crate::loader::lock_guard::lock_tracked(&win32_user::WIN32_USER)
                        .find_window(arg0 as u32)
                        .map(|win| (win.x, win.y, win.w as i32, win.h as i32))
                        .unwrap_or((0, 0, 800, 600));
                    let rect = arg1 as *mut i32;
                    unsafe {
                        *rect.add(0) = x;
                        *rect.add(1) = y;
                        *rect.add(2) = x + w;
                        *rect.add(3) = y + h;
                    }
                }
                1
            }
            0x2023 => { 1 }  // ClientToScreen
            0x2024 => { 1 }  // ScreenToClient
            0x2025 => {       // GetCursorPos → write current mouse position to POINT*
                if arg0 > 0x1000 {
                    let s = crate::task::mouse::MOUSE_STATE.lock();
                    unsafe {
                        *(arg0 as *mut i32)           = s.x as i32;
                        *((arg0 + 4) as *mut i32)     = s.y as i32;
                    }
                }
                1
            }
            0x2026 => { arg0 }  // SetCursor → return previous cursor (return arg = handle)
            0x2027 => { 1 }  // SetWindowPos → TRUE
            0x2028 => { 1 }  // RedrawWindow → TRUE
            0x2029 => { 1 }  // SetForegroundWindow → TRUE
            0x202A => { 1 }  // GetActiveWindow → fake HWND 1
            0x202B => { 0 }  // IsIconic → FALSE
            0x202C => { 1 }  // IsProcessDPIAware → TRUE
            0x202D => { 0 }  // SetCapture → NULL (previous capture)
            0x202E => { 1 }  // ReleaseCapture → TRUE
            0x202F => { 1 }  // ValidateRect → TRUE
            0x2030 => { 0 }  // SendMessageW → 0
            0x2031 => { 1 }  // PostMessageW → TRUE
            0x2032 => { 0 }  // CallWindowProcW → 0
            0x2033 => win32_user::dispatch_win32_user_syscall(0x4002, arg0, 0, 0, 0), // DestroyWindow
            0x2034 | 0x2035 | 0x2036 => { 1 }  // MonitorFrom* → fake monitor handle 1
            0x2037 => { 1 }  // GetMonitorInfoW → TRUE (struct stays zeroed)
            0x2038 => { 1 }  // OpenClipboard → TRUE
            0x2039 => { 1 }  // CloseClipboard → TRUE
            0x203A => { 1 }  // EmptyClipboard → TRUE
            0x203B => { 0 }  // GetClipboardData → NULL
            0x203C => { arg1 }  // SetClipboardData → return handle arg
            0x203D => { 0 }  // IsClipboardFormatAvailable → FALSE
            0x203E => { 0xC001 }  // RegisterClipboardFormatW → unique format ID
            0x203F => { 1 }  // SystemParametersInfoA → TRUE
            0x2040 => { 0 }  // GetKeyState → 0 (key not pressed)
            0x2041 => { 0 }  // GetAsyncKeyState → 0
            0x2042 => { 0 }  // MapVirtualKeyW → 0
            0x2043 => { 0 }  // GetWindowTextW → 0 chars
            0x2044 => win32_user::dispatch_win32_user_syscall(0x4005, arg0, arg1, 0, 0), // SetWindowTextW
            0x2045 => { 0 }  // GetWindowTextLengthW → 0
            0x2046 => { 1 }  // ShowCursor → 1 (display count)
            0x2047 => { 1 }  // ClipCursor → TRUE
            0x2048 => { 1 }  // GetClipCursor → TRUE
            0x2049 => { 1 }  // FlashWindowEx → TRUE
            0x204A => { 1 }  // RegisterRawInputDevices → TRUE
            0x204B => { 1 }  // RegisterTouchWindow → TRUE
            0x204C => { 1 }  // TrackMouseEvent → TRUE
            0x204D => { 1 }  // EnableMenuItem → previous state
            0x204E => { 1 }  // GetSystemMenu → fake menu handle
            0x204F => { 0 }  // GetPropW → NULL
            0x2050 => { 1 }  // SetPropW → TRUE
            0x2051 => { 0 }  // RemovePropW → NULL
            0x2052 => { 0xC002 }  // RegisterWindowMessageA → unique message ID

            // ── LoadStringW/A + menu stubs (Patch 2) ──────────────────────
            0x2060 => {
                // LoadStringW(hInstance, uID, lpBuffer, cchBufferMax)
                if arg2 > 0x1000 && arg3 > 0 { unsafe { *(arg2 as *mut u16) = 0; } }
                0
            }
            0x2061 => { 0 }   // GetMenuString
            0x2062 => { 1 }   // AppendMenuW
            0x2063 => { 2 }   // CreateMenu → fake HMENU 2
            0x2064 => { 3 }   // CreatePopupMenu → fake HMENU 3
            0x2065 => { 1 }   // DestroyMenu
            0x2066 => { 1 }   // SetMenu
            0x2067 => { 1 }   // DrawMenuBar
            0x2068 => { 4 }   // LoadMenuW → fake HMENU 4
            0x2069 => { 5 }   // LoadAcceleratorsW → fake HACCEL 5
            0x206A => { 0 }   // TranslateAcceleratorW → not translated
            0x206B => { arg1 } // CharUpperBuffW → nLength
            0x206C => { arg1 } // CharLowerBuffW → nLength
            0x206D => { 1 }    // IsCharAlphaNumericW
            0x206E | 0x206F => {
                if arg0 > 0x1000 { unsafe { *(arg0 as *mut u16) = 0; } }
                0
            }  // wsprintfW / wvsprintfW

            // ── Kernel32 Patch 7 stubs (0x1125–0x1170) ─────────────────────

            0x1125 => {
                // CreateMutexExW — return a fake non-zero HANDLE so callers don't abort
                static MUTEX_CTR: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0xF000_0001);
                MUTEX_CTR.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
            }
            0x1126 => {
                // MulDiv(nNumber, nNumerator, nDenominator)
                let n = arg0 as i64;
                let num = arg1 as i64;
                let den = arg2 as i64;
                if den == 0 { return (-1i32) as u64; }
                let result = (n * num + den / 2) / den;
                result as i32 as u64
            }
            0x1127 => { 1 }  // HeapSetInformation → TRUE
            0x1128 => {
                // GetTickCount / GetTickCount64
                crate::interrupts::TICKS.load(core::sync::atomic::Ordering::Relaxed)
            }
            0x1129 => {
                // GetFileAttributesExW(lpFileName, fInfoLevel, lpFileInformation)
                // Write a plausible WIN32_FILE_ATTRIBUTE_DATA to arg2
                if arg2 > 0x1000 {
                    unsafe { core::ptr::write_bytes(arg2 as *mut u8, 0, 36); }
                    // dwFileAttributes = FILE_ATTRIBUTE_NORMAL (0x80)
                    unsafe { *(arg2 as *mut u32) = 0x80; }
                }
                1 // TRUE
            }
            0x112A => {
                // GetFileAttributesA — return INVALID_FILE_ATTRIBUTES for unknown
                0xFFFF_FFFF_u64
            }
            0x112B => {
                // FoldStringW — copy src to dst unchanged (stub: no case folding)
                if arg2 > 0x1000 && arg3 > 0x1000 {
                    let src = arg2 as *const u16;
                    let dst = arg3 as *mut u16;
                    let max_len = (arg1 as usize).min(4096);
                    let mut n = 0usize;
                    unsafe {
                        while n < max_len {
                            let ch = *src.add(n);
                            *dst.add(n) = ch;
                            n += 1;
                            if ch == 0 { break; }
                        }
                    }
                    n as u64
                } else { 0 }
            }
            0x112C => { 0x0409 }  // GetUserDefaultUILanguage → en-US
            0x112D => { 0 }       // DebugBreak / DebugBreakProcess → no-op
            0x112E => {
                // OutputDebugStringA/W (one ID): the serial log is the debugger.
                // A wide string shows up as a zero second byte.
                crate::serial_println!("[WIN32] OutputDebugString: {}", read_debug_string(arg0));
                0
            }
            0x112F => {
                // FindFirstFileW(lpFileName, lpFindFileData) → INVALID_HANDLE_VALUE
                // Write empty WIN32_FIND_DATAW (592 bytes) so caller doesn't read garbage
                if arg1 > 0x1000 {
                    unsafe { core::ptr::write_bytes(arg1 as *mut u8, 0, 592); }
                }
                0xFFFF_FFFF_FFFF_FFFFu64 // INVALID_HANDLE_VALUE
            }
            0x1130 => { 1 }  // GetFileType → FILE_TYPE_CHAR (console)
            0x1131 => { 0 }  // GetFileSize → 0
            0x1132 => { 0 }  // SetFilePointer → 0
            0x1133 | 0x1134 => { 1 }  // LockFile / UnlockFile → TRUE
            0x1135 => { 0 }  // CopyFileW → FALSE (no VFS write)
            0x1136 => { 0 }  // MoveFileW → FALSE
            0x1137 => { 3 }  // GetDriveTypeW → DRIVE_FIXED
            0x1138 => { 1 }  // GetVolumeInformationW → TRUE stub
            0x1139 => {
                // GetDiskFreeSpaceExW — write 1GB free to all three ULARGE_INTEGER ptrs
                for ptr in [arg1, arg2, arg3] {
                    if ptr > 0x1000 { unsafe { *(ptr as *mut u64) = 1 << 30; } }
                }
                1
            }
            0x113A => { 1 }   // SetCurrentDirectoryW → TRUE
            0x113B | 0x113C => {
                // GetLongPathNameW / GetShortPathNameW — copy src to dst unchanged
                if arg1 > 0x1000 && arg2 > 0x1000 {
                    let mut n = 0usize;
                    unsafe {
                        while n < (arg3 as usize).min(4096) {
                            let ch = *(arg1 as *const u16).add(n);
                            *(arg2 as *mut u16).add(n) = ch;
                            n += 1;
                            if ch == 0 { break; }
                        }
                    }
                    n as u64
                } else { 0 }
            }
            0x113D => { 0 }   // ExpandEnvironmentStringsW → 0 (no expansion)
            0x113E => { 0 }   // GetPrivateProfileStringW → 0 (not found)
            0x113F => { 1 }   // WritePrivateProfileStringW → TRUE
            0x1140 | 0x1141 => { 0 }  // OpenFileMappingW / GetMappedFileNameW → fail
            0x1142 => {
                // GetProcessTimes — write zero FILETIME structs
                for ptr in [arg1, arg2, arg3] {
                    if ptr > 0x1000 { unsafe { *(ptr as *mut u64) = 0; } }
                }
                1
            }
            0x1143 => {
                // RaiseException — log and treat as process termination
                crate::serial_println!("[KERNEL32] RaiseException code={:#x} flags={:#x}", arg0, arg1);
                if let Some(proc) = crate::process::PROCESSOR.lock().get_active() {
                    proc.terminate(arg0 as i32);
                }
                crate::interrupts::USER_PROCESS_ACTIVE.store(false, core::sync::atomic::Ordering::Relaxed);
                0
            }
            0x1144 => { 0 }  // GetProcessMitigationPolicy → FALSE (not supported)

            // Events / synchronisation
            0x1145 => { 1 }  // SetEvent → TRUE
            0x1146 => { 1 }  // ResetEvent → TRUE
            0x1147 => {
                // CreateEventExW — return a fake non-zero event handle
                static EVT_CTR: core::sync::atomic::AtomicU64 =
                    core::sync::atomic::AtomicU64::new(0xE000_0001);
                EVT_CTR.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
            }

            // COM stubs
            0x1148 => { 0 }  // CoWaitForMultipleHandles → S_OK
            0x1149 => { 0 }  // PropVariantClear → S_OK
            0x114A => {
                // CoTaskMemAlloc(cb) — allocate via VirtualAlloc
                let size = arg0.max(16);
                let ptr = crate::nt_memory::dispatch_nt_memory_syscall(0x0018, 0, size, 0x3000, 0x04);
                if ptr != 0 {
                    let pages = ((size as usize + 4095) / 4096).max(1);
                    unsafe { core::ptr::write_bytes(ptr as *mut u8, 0, pages * 4096); }
                }
                ptr
            }
            0x114B => { 0 }  // CoTaskMemFree → void
            0x114C => { 0 }  // CoCreateFreeThreadedMarshaler → S_OK stub
            0x114D => {
                // CoCreateGuid(pguid) — write a deterministic pseudo-GUID
                if arg0 > 0x1000 {
                    let tick = crate::interrupts::TICKS.load(core::sync::atomic::Ordering::Relaxed);
                    let guid = arg0 as *mut u64;
                    unsafe { *guid = tick ^ 0xDEAD_BEEF_CAFE_1234; *guid.add(1) = tick.wrapping_add(1); }
                }
                0  // S_OK
            }

            // WinRT stubs (all return S_OK = 0, or E_NOTIMPL = 0x80004001)
            0x114E => { 0 }  // RoInitialize → S_OK
            0x114F => { 0 }  // RoUninitialize
            0x1150 => { 0x8000_4001u64 }  // RoGetActivationFactory → E_NOTIMPL
            0x1151 => {
                // WindowsCreateString(src, len, phstring)
                // phstring = pointer where we store an HSTRING (just store a copy of src ptr)
                if arg2 > 0x1000 { unsafe { *(arg2 as *mut u64) = arg0; } }
                0  // S_OK
            }
            0x1152 => { 0 }  // WindowsDeleteString → S_OK
            0x1153 => { arg0 }  // WindowsGetStringRawBuffer → return the ptr itself
            0x1154 => {
                // WindowsCreateStringReference — write src ptr as HSTRING
                if arg3 > 0x1000 { unsafe { *(arg3 as *mut u64) = arg0; } }
                0  // S_OK
            }
            0x1155 => { 0 }  // SetRestrictedErrorInfo / RoGetMatchingRestrictedErrorInfo

            // CRT _o_ private wrappers
            0x1156 => {
                // _o__errno() — return pointer to a static errno int
                static ERRNO_VAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
                ERRNO_VAL.as_ptr() as u64
            }
            0x1157 => {
                // abort() / terminate()
                crate::serial_println!("[CRT] abort() called — terminating process");
                if let Some(proc) = crate::process::PROCESSOR.lock().get_active() {
                    proc.terminate(-1);
                }
                crate::interrupts::USER_PROCESS_ACTIVE.store(false, core::sync::atomic::Ordering::Relaxed);
                0
            }
            0x1158 => { 0 }  // _callnewh → 0 (no new-handler)
            0x1159 => { 0 }  // _cexit → 0
            0x115A => { 0 }  // _configthreadlocale → 0
            0x115B => { 0 }  // _configure_wide_argv → 0
            0x115C => { 0 }  // _crt_atexit → 0 (don't register)
            0x115D => {
                // _get_wide_winmain_command_line — return pointer to empty wide string
                // (re-use argv_data which has L"VEILAPP" at argv_ptr+0x20)
                let argv_ptr = active_nt_env().argv_ptr;
                if argv_ptr > 0x1000 { argv_ptr + 0x20 } else { 0 }
            }
            0x115E => { 0 }  // _initenv → 0
            0x115F => { 0 }  // _invalid_parameter_noinfo_noreturn → 0 (don't panic)
            0x1160 => { 0 }  // _set_app_type → 0
            0x1161 => { 0 }  // _set_fmode → 0
            0x1162 | 0x1163 => {
                // wcscpy_s / wcsncpy_s(dst, dstSize, src, count)
                if arg0 > 0x1000 && arg2 > 0x1000 {
                    let max = (arg1 as usize).min(arg3 as usize).min(4096);
                    unsafe {
                        let src = arg2 as *const u16;
                        let dst = arg0 as *mut u16;
                        let mut i = 0;
                        while i < max { let c = *src.add(i); *dst.add(i) = c; i += 1; if c == 0 { break; } }
                        if i == max { *dst.add(max-1) = 0; }
                    }
                }
                0
            }
            0x1164 => {
                // wcsnlen(s, maxlen) — count wide chars up to maxlen
                if arg0 > 0x1000 {
                    let max = (arg1 as usize).min(65536);
                    let ptr = arg0 as *const u16;
                    let mut n = 0;
                    unsafe { while n < max && *ptr.add(n) != 0 { n += 1; } }
                    n as u64
                } else { 0 }
            }
            0x1165 | 0x1166 => {
                // memcpy_s / memmove_s(dst, dstSize, src, count)
                if arg0 > 0x1000 && arg2 > 0x1000 {
                    let n = (arg1 as usize).min(arg3 as usize);
                    unsafe { core::ptr::copy(arg2 as *const u8, arg0 as *mut u8, n); }
                }
                0
            }
            0x1167 => {
                // memmove(dst, src, n)
                if arg0 > 0x1000 && arg1 > 0x1000 {
                    unsafe { core::ptr::copy(arg1 as *const u8, arg0 as *mut u8, arg2 as usize); }
                }
                arg0
            }
            0x1168 => {
                // memcmp(a, b, n)
                if arg0 > 0x1000 && arg1 > 0x1000 {
                    let n = arg2 as usize;
                    let a = arg0 as *const u8;
                    let b = arg1 as *const u8;
                    unsafe {
                        for i in 0..n {
                            let diff = *a.add(i) as i32 - *b.add(i) as i32;
                            if diff != 0 { return diff as u64; }
                        }
                    }
                }
                0
            }
            0x1169 => {
                // strlen(s)
                if arg0 > 0x1000 {
                    let ptr = arg0 as *const u8;
                    let mut n = 0;
                    unsafe { while *ptr.add(n) != 0 { n += 1; } }
                    n as u64
                } else { 0 }
            }
            0x116A => {
                // strncpy_s(dst, dstSize, src, count)
                if arg0 > 0x1000 && arg2 > 0x1000 {
                    let max = (arg1 as usize).min(arg3 as usize).min(4096);
                    unsafe {
                        let src = arg2 as *const u8;
                        let dst = arg0 as *mut u8;
                        let mut i = 0;
                        while i < max { let c = *src.add(i); *dst.add(i) = c; i += 1; if c == 0 { break; } }
                        if i == max { *dst.add(max-1) = 0; }
                    }
                }
                0
            }
            0x116B => {
                // wcscmp(s1, s2)
                if arg0 > 0x1000 && arg1 > 0x1000 {
                    let a = arg0 as *const u16;
                    let b = arg1 as *const u16;
                    unsafe {
                        let mut i = 0;
                        loop {
                            let ca = *a.add(i);
                            let cb = *b.add(i);
                            if ca != cb { return (ca as i32 - cb as i32) as u64; }
                            if ca == 0 { break; }
                            i += 1;
                        }
                    }
                }
                0
            }
            0x116C => { 0 }   // api-ms-win-shcore-path Ordinal#170 → stub
            0x116D => { 0 }   // SHStrDupW → NULL (no alloc)
            0x116E => { 0 }   // EventProviderEnabled → FALSE (disabled)
            0x116F => { 1 }   // PathIsFileSpecW → TRUE (stub)
            0x1170 => { arg0 } // PathFindExtensionW → return ptr itself (stub)

            // ── User32 Patch 7 stubs (0x2070–0x20A6) ───────────────────────

            0x2070 => { 0 }   // GetMenu → NULL (no menu bar; app will use CreateMenu)
            0x2071 => { 0 }   // GetSubMenu → NULL
            0x2072 => { 0 }   // CheckMenuItem → MF_UNCHECKED
            0x2073 => { 0 }   // GetMenuItemCount → 0
            0x2074 => { 0 }   // GetMenuItemID → -1
            0x2075 => { 1 }   // InsertMenuItemW → TRUE
            0x2076 => { 1 }   // ModifyMenuW → TRUE
            0x2077 => { 1 }   // RemoveMenu → TRUE
            0x2078 => { 1 }   // SetMenuDefaultItem → TRUE
            0x2079 | 0x207A => { 0 }  // TrackPopupMenu / TrackPopupMenuEx → 0 (dismissed)
            0x207B | 0x207C => { 1 }  // GetMenuItemInfoW / SetMenuItemInfoW → TRUE
            0x207D => { 1 }   // MessageBeep → TRUE (no speaker)
            0x207E => { 96 }  // GetDpiForWindow / GetDpiForSystem / GetDpiForMonitor → 96 DPI
            0x207F => { 0 }   // GetDlgCtrlID → 0
            0x2080 => { 0x0409 }  // GetKeyboardLayout → en-US HKL
            0x2081 => { 1 }   // GetKeyboardState → TRUE (all keys up = zeroed buffer)
            0x2082 => { 1 }   // SetKeyboardState → TRUE
            0x2083 => { 0 }   // ToUnicodeEx → 0 (no translation)
            0x2084 => { 0 }   // VkKeyScanW → -1 (not found)
            0x2085 => { 0 }   // GetKeyNameTextW → 0
            0x2086 => { 1 }   // SetActiveWindow → fake HWND 1
            0x2087 => { 1 }   // BringWindowToTop → TRUE
            0x2088 => { 1 }   // IsWindow → TRUE (assume valid)
            0x2089 => { 1 }   // IsWindowEnabled → TRUE
            0x208A => { 1 }   // IsWindowVisible → TRUE
            0x208B => { 1 }   // EnableWindow → TRUE
            0x208C => { 0 }   // GetParent → NULL
            0x208D => { 0 }   // SetParent → NULL
            0x208E => { 0 }   // GetWindow → NULL
            0x208F | 0x2090 => { 0 }  // FindWindowW / FindWindowExW → NULL
            0x2091 | 0x2092 => { 0 }  // DialogBoxParamW / CreateDialogParamW → 0
            0x2093 => { 1 }   // EndDialog → TRUE
            0x2094 => { 0 }   // GetDlgItem → NULL
            0x2095 => { 1 }   // SetDlgItemTextW → TRUE
            0x2096 => { 0 }   // GetDlgItemTextW → 0 chars
            0x2097 => { 0 }   // SendDlgItemMessageW → 0
            0x2098 | 0x2099 => { 0 }  // GetScrollInfo / SetScrollInfo
            0x209A | 0x209B => { 0 }  // GetScrollPos / SetScrollPos
            0x209C | 0x209D => { 0 }  // ScrollWindow / ScrollWindowEx
            0x209E => { 1 }   // CreateCaret → TRUE
            0x209F => { 1 }   // DestroyCaret → TRUE
            0x20A0 => { 1 }   // SetCaretPos → TRUE
            0x20A1 | 0x20A2 => { 1 }  // ShowCaret / HideCaret → TRUE
            0x20A3 => {
                // GetCaretPos(POINT*) — write 0,0
                if arg0 > 0x1000 { unsafe { *(arg0 as *mut u64) = 0; } }
                1
            }
            0x20A4 | 0x20A5 | 0x20A6 => { 1 }  // OpenIcon / CloseWindow / ArrangeIconicWindows

            // COMCTL32 stubs
            0x2171 => { 0 }   // CreateStatusWindowW → NULL (no status bar)
            0x2172 => { 0 }   // Ordinal#345 → stub
            0x2173 => { 1 }   // InitCommonControlsEx → TRUE

            // ── ntdll extras ─────────────────────────────────────────────────
            0x00B0 => { 0 }   // RtlNtStatusToDosError → ERROR_SUCCESS
            0x0033 => { nt_objects::STATUS_NOT_IMPLEMENTED }  // NtOpenFile
            0x0007 => { nt_objects::STATUS_NOT_IMPLEMENTED }  // NtDeviceIoControlFile
            0x003D => { nt_objects::STATUS_NOT_IMPLEMENTED }  // NtCancelIoFileEx
            0x001A => { nt_objects::STATUS_NOT_IMPLEMENTED }  // NtCreateNamedPipeFile

            // ── ws2_32 extras ─────────────────────────────────────────────────
            0x8006 => { 0 }  // freeaddrinfo → void
            0x8007 => { 0xB7B7 }  // getaddrinfo → WSAHOST_NOT_FOUND (stub)
            0x8008 => { 0 }  // closesocket → 0 (SOCKET_ERROR would be -1)
            0x8009 => { 0 }  // getsockopt
            0x800A => { 0 }  // ioctlsocket
            0x800B => { 0 }  // WSAIoctl
            0x800C => { 0xFFFF_FFFFu64 }  // bind → SOCKET_ERROR
            0x800D => { 0xFFFF_FFFFu64 }  // accept → INVALID_SOCKET
            0x800E => { 0xFFFF_FFFFu64 }  // listen → SOCKET_ERROR
            0x800F => { 0xFFFF_FFFFu64 }  // WSASocketW → INVALID_SOCKET
            0x8010 => { 0 }  // shutdown
            0x8011 => { 0 }  // WSACleanup
            0x8012 => { 0 }  // WSAGetLastError → 0 (no error)

            // ── ole32 extras ──────────────────────────────────────────────────
            0x7004 => { 0 }  // CoInitializeEx → S_OK
            0x7005 => { 0 }  // CoUninitialize → void
            0x7006 => { 0 }  // OleInitialize → S_OK
            0x7007 | 0x7008 => { 0 }  // RegisterDragDrop / RevokeDragDrop

            // ── vcruntime extras ──────────────────────────────────────────────
            0x9306 => {       // memcmp
                let a   = arg0 as *const u8;
                let b   = arg1 as *const u8;
                let len = arg2 as usize;
                let mut result = 0i64;
                for i in 0..len {
                    let va = unsafe { *a.add(i) } as i64;
                    let vb = unsafe { *b.add(i) } as i64;
                    if va != vb { result = va - vb; break; }
                }
                result as u64
            }
            0x9307 => {       // wcslen
                if arg0 < 0x1000 { return 0; }
                let ptr = arg0 as *const u16;
                let mut len = 0usize;
                while len < 65535 && unsafe { *ptr.add(len) } != 0 { len += 1; }
                len as u64
            }
            0x9403 | 0x9404 => { 0 }  // __C_specific_handler / __CxxFrameHandler3 → 0
            0x9405 | 0x9406 => { 0 }  // __current_exception / __current_exception_context → NULL

            // ── crt_math float (f32) functions ────────────────────────────────
            // Same approximations as the f64 path above but operating on f32
            // bits packed into the low 32 bits of arg0.
            // 0x9508=sinf 0x9509=cosf 0x950A=tanf 0x950B=sqrtf
            // 0x950C=ceilf 0x950D=floorf 0x950E=roundf 0x950F=truncf
            // 0x9510=fmodf 0x9511=fabsf 0x9512=expf 0x9513=logf
            // 0x9514=log2f 0x9515=log10f 0x9516=powf
            0x9508 => {  // sinf
                let x = f32::from_bits(arg0 as u32) as f64;
                const TWO_PI: f64 = 6.283185307179586;
                let xr = x - TWO_PI * libm_round(x / TWO_PI);
                let r = bhaskara_sin(xr) as f32;
                r.to_bits() as u64
            }
            0x9509 => {  // cosf
                let x = f32::from_bits(arg0 as u32) as f64;
                const TWO_PI: f64 = 6.283185307179586;
                const HALF_PI: f64 = 1.5707963267948966;
                let xr = (x + HALF_PI) - TWO_PI * libm_round((x + HALF_PI) / TWO_PI);
                let r = bhaskara_sin(xr) as f32;
                r.to_bits() as u64
            }
            0x950A => {  // tanf
                let x = f32::from_bits(arg0 as u32) as f64;
                const TWO_PI: f64 = 6.283185307179586;
                const HALF_PI: f64 = 1.5707963267948966;
                let xr = x - TWO_PI * libm_round(x / TWO_PI);
                let s = bhaskara_sin(xr);
                let c = bhaskara_sin(xr + HALF_PI - TWO_PI * libm_round((xr + HALF_PI) / TWO_PI));
                let r = if c.abs() < 1e-10 { s } else { s / c };
                (r as f32).to_bits() as u64
            }
            0x950B => {  // sqrtf
                let x = f32::from_bits(arg0 as u32) as f64;
                if x < 0.0 { return (f32::NAN).to_bits() as u64; }
                if x == 0.0 { return 0; }
                let r = software_sqrt(x) as f32;
                r.to_bits() as u64
            }
            0x950C => {  // ceilf
                let x = f32::from_bits(arg0 as u32);
                let t = x as i32 as f32;
                let r = if t < x { t + 1.0 } else { t };
                r.to_bits() as u64
            }
            0x950D => {  // floorf
                let x = f32::from_bits(arg0 as u32);
                let t = x as i32 as f32;
                let r = if t > x { t - 1.0 } else { t };
                r.to_bits() as u64
            }
            0x950E => {  // roundf — round half away from zero
                let x = f32::from_bits(arg0 as u32);
                let r = if x >= 0.0 { (x + 0.5) as i32 as f32 }
                        else        { (x - 0.5) as i32 as f32 };
                r.to_bits() as u64
            }
            0x950F => {  // truncf — round toward zero
                let x = f32::from_bits(arg0 as u32);
                let r = x as i32 as f32;
                r.to_bits() as u64
            }
            0x9510 => {  // fmodf — remainder
                let x = f32::from_bits(arg0 as u32);
                let y = f32::from_bits(arg1 as u32);
                if y == 0.0 { return (f32::NAN).to_bits() as u64; }
                let r = x - (x / y) as i32 as f32 * y;
                r.to_bits() as u64
            }
            0x9511 => {  // fabsf — absolute value
                let x = f32::from_bits(arg0 as u32);
                let r = if x < 0.0 { -x } else { x };
                r.to_bits() as u64
            }
            0x9512 => {  // expf(x) — e^x in f32
                let x = f32::from_bits(arg0 as u32) as f64;
                if !x.is_finite() { return arg0 & 0xFFFF_FFFF; }
                let r = software_exp(x) as f32;
                r.to_bits() as u64
            }
            0x9513 => {  // logf(x) — natural log in f32
                let x = f32::from_bits(arg0 as u32) as f64;
                if x <= 0.0 { return f32::NAN.to_bits() as u64; }
                if !x.is_finite() { return arg0 & 0xFFFF_FFFF; }
                let r = software_ln(x) as f32;
                r.to_bits() as u64
            }
            0x9514 => {  // log2f(x)
                let x = f32::from_bits(arg0 as u32) as f64;
                if x <= 0.0 { return f32::NAN.to_bits() as u64; }
                if !x.is_finite() { return arg0 & 0xFFFF_FFFF; }
                // log2(x) = ln(x) / ln(2)
                let r = (software_ln(x) / core::f64::consts::LN_2) as f32;
                r.to_bits() as u64
            }
            0x9515 => {  // log10f(x)
                let x = f32::from_bits(arg0 as u32) as f64;
                if x <= 0.0 { return f32::NAN.to_bits() as u64; }
                if !x.is_finite() { return arg0 & 0xFFFF_FFFF; }
                // log10(x) = ln(x) / ln(10)
                const LN10: f64 = 2.302585092994046;
                let r = (software_ln(x) / LN10) as f32;
                r.to_bits() as u64
            }
            0x9516 => {  // powf(base, exp)
                let base = f32::from_bits(arg0 as u32) as f64;
                let exp  = f32::from_bits(arg1 as u32) as f64;
                if exp == 0.0 { return (1.0f32).to_bits() as u64; }
                if base == 0.0 { return 0; }
                let exp_i = exp as i64;
                if exp_i as f64 == exp && exp_i.abs() < 64 {
                    let mut result = 1.0f64;
                    let mut base_p = if exp_i < 0 { 1.0 / base } else { base };
                    let mut n = exp_i.unsigned_abs();
                    while n > 0 {
                        if n & 1 != 0 { result *= base_p; }
                        base_p *= base_p;
                        n >>= 1;
                    }
                    (result as f32).to_bits() as u64
                } else {
                    // Non-integer exponent: exp(exp * ln(base)).
                    if base < 0.0 {
                        return (f32::NAN).to_bits() as u64;
                    }
                    let ln_base = software_ln(base.max(f64::MIN_POSITIVE));
                    (software_exp(exp * ln_base) as f32).to_bits() as u64
                }
            }

            // ── crt_runtime extras ────────────────────────────────────────────
            0x9105 | 0x9106 | 0x9107 | 0x9108 => { 0 }  // onexit / cexit stubs
            0x9109 => { 0 }  // _set_app_type
            0x910A | 0x910B | 0x910C => { 0 }  // _configure_narrow_argv etc.
            0x910D => {
                // __p___argc → return pointer to argc (int = 1)
                active_nt_env().argc_ptr
            }
            0x910E => {
                // __p___argv → return pointer to argv (char**)
                active_nt_env().argv_ptr
            }
            0x910F => { 0 }  // _seh_filter_exe
            0x9110 => {       // terminate → terminate process, don't freeze kernel
                crate::serial_println!("[CRT] terminate() called");
                if let Some(proc) = crate::process::PROCESSOR.lock().get_active() {
                    proc.terminate(-3);
                }
                crate::interrupts::USER_PROCESS_ACTIVE.store(false, core::sync::atomic::Ordering::Relaxed);
                unsafe { crate::loader::return_from_usermode() }
            }
            0x9111 => {           // exit / _exit → call ExitProcess
                println!("[CRT] exit({})", arg0);
                if let Some(proc) = crate::process::PROCESSOR.lock().get_active() {
                    proc.terminate(arg0 as i32);
                }
                crate::interrupts::USER_PROCESS_ACTIVE.store(false, core::sync::atomic::Ordering::Relaxed);
                unsafe { crate::loader::return_from_usermode() }
            }
            0x9112 => { 0 }  // strerror → NULL

            // ── crt_stdio extras ──────────────────────────────────────────────
            0x9204 => {
                // __acrt_iob_func(index) — returns FILE* for stdin(0), stdout(1), stderr(2)
                // We return a fake but valid-looking address. The CRT only needs
                // this to be non-null for fprintf/vfprintf checks.
                static mut FAKE_IOB: [u64; 8] = [0; 8];
                let idx = arg0 as usize;
                let base = &raw const FAKE_IOB as u64;
                if idx < 3 { base + (idx as u64 * 8) } else { 0 }
            }
            0x9205 => { 0 }  // _set_fmode
            0x9206 => {
                // __p__commode → return pointer to a static int (value 0)
                static mut COMMODE: i32 = 0;
                &raw const COMMODE as u64
            }

            _ => {
                println!("[WINDOWS] Unhandled NT syscall: {:#X}", id);
                nt_objects::STATUS_NOT_IMPLEMENTED
            }
        }
    }
}

// =====================================================================
// -----| Software Math Helpers (no_std, no libm) |-----
// =====================================================================
//
// These are used by the CRT math syscall stubs (0x9501–0x9516).
// They are NOT exposed to user code directly — they back the syscall
// translation layer only.
//
// Precision targets:
//   bhaskara_sin  — ~0.1% relative error for |x| < π  (game-quality)
//   software_sqrt — ~14 significant bits via 4× Newton steps  (good enough
//                   for normalisation and lighting, no divide-by-zero risk)
//   libm_round    — exact for finite f64

/// Round f64 to nearest integer (ties away from zero), without libm.
#[inline(always)]
fn libm_round(x: f64) -> f64 {
    if x >= 0.0 {
        let t = x as i64 as f64;
        if x - t >= 0.5 { t + 1.0 } else { t }
    } else {
        let t = x as i64 as f64;
        if t - x >= 0.5 { t - 1.0 } else { t }
    }
}

/// Bhaskara I sine approximation.
/// Input must be pre-reduced to [-π, π].
/// Maximum relative error ≈ 0.165% — good enough for game rendering.
#[inline]
fn bhaskara_sin(x: f64) -> f64 {
    const PI:   f64 = 3.141592653589793;
    const PI2:  f64 = PI * PI;

    // Reflect negative half: sin(-x) = -sin(x)
    let (x, sign) = if x < 0.0 { (-x, -1.0f64) } else { (x, 1.0f64) };

    // Reduce to [0, π]
    let x = if x > PI { 2.0 * PI - x } else { x };

    // Bhaskara I formula: 16x(π-x) / (5π²-4x(π-x))
    let num = 16.0 * x * (PI - x);
    let den = 5.0 * PI2 - 4.0 * x * (PI - x);
    if den.abs() < 1e-15 { return sign; } // avoid /0 at x≈0 or x≈π
    sign * num / den
}

/// Software square root via Newton-Raphson (4 iterations).
/// Input must be positive and finite; caller is responsible for edge cases.
/// Relative error after 4 iterations: < 1 ULP for most inputs.
#[inline]
fn software_sqrt(x: f64) -> f64 {
    // Initial estimate from the IEEE 754 bit pattern.
    // Halving the biased exponent gives a good starting approximation.
    let bits = x.to_bits();
    let estimate_bits = (bits >> 1).wrapping_add(0x1FF8_0000_0000_0000u64);
    let mut r = f64::from_bits(estimate_bits);

    // Newton-Raphson: r ← (r + x/r) / 2  — converges quadratically
    r = 0.5 * (r + x / r);
    r = 0.5 * (r + x / r);
    r = 0.5 * (r + x / r);
    r = 0.5 * (r + x / r);
    r
}

/// Software natural logarithm.
///
/// Algorithm: decompose x = 2^k * m  where m ∈ [1, 2), then use a
/// degree-5 minimax polynomial for ln(m) on [1, 2).
///   ln(x) = k·ln(2) + ln(m)
///
/// Maximum relative error over the full positive range: < 5×10⁻⁷
/// (about 20 bits of accuracy — adequate for game physics and lighting).
///
/// Caller must ensure x > 0 and x is finite.
#[inline]
fn software_ln(x: f64) -> f64 {
    const LN2: f64 = 0.6931471805599453;

    // Extract biased exponent and mantissa.
    let bits = x.to_bits();
    let exp_biased = ((bits >> 52) & 0x7FF) as i32;
    // Rebuild mantissa in [1, 2) by forcing exponent = 1023 (bias).
    let mantissa = f64::from_bits((bits & 0x000F_FFFF_FFFF_FFFFu64) | 0x3FF0_0000_0000_0000u64);
    let k = (exp_biased - 1023) as f64;

    // Polynomial approximation of ln(m) for m ∈ [1, 2).
    // Transform t = (m - 1) / (m + 1) so the range is [0, 1/3) and use
    // the identity  ln(m) = 2·(t + t³/3 + t⁵/5 + t⁷/7 + …)
    // We use 5 terms, giving error < 4×10⁻⁷ for m ∈ [1, 2).
    let t  = (mantissa - 1.0) / (mantissa + 1.0);
    let t2 = t * t;
    let ln_m = 2.0 * t * (1.0 + t2 * (1.0/3.0 + t2 * (1.0/5.0 + t2 * (1.0/7.0 + t2 / 9.0))));

    k * LN2 + ln_m
}

/// Software e^x (natural exponential).
///
/// Algorithm: reduce x = k·ln(2) + r, r ∈ [-½ln2, ½ln2], compute
/// 2^k exactly via bit manipulation and e^r via a degree-6 Taylor series.
///
/// Maximum relative error: < 2×10⁻⁷ for |x| ≤ 709 (the double overflow limit).
///
/// Caller is responsible for edge cases (NaN, Inf, underflow/overflow).
#[inline]
fn software_exp(x: f64) -> f64 {
    const LN2:     f64 = 0.6931471805599453;
    const INV_LN2: f64 = 1.4426950408889634;
    const EXP_MAX: f64 = 709.782; // exp(x) overflows f64 above this

    if x > EXP_MAX  { return f64::INFINITY; }
    if x < -745.0   { return 0.0; }

    // k = round(x / ln2), r = x - k·ln2  so |r| ≤ ½ln2
    let k = libm_round(x * INV_LN2);
    let r = x - k * LN2;

    // Taylor series: e^r ≈ 1 + r + r²/2! + r³/3! + r⁴/4! + r⁵/5! + r⁶/6!
    let r2 = r * r;
    let er = 1.0 + r + r2 * (0.5 + r * (1.0/6.0 + r * (1.0/24.0
           + r * (1.0/120.0 + r * (1.0/720.0)))));

    // Multiply by 2^k using exponent field arithmetic — exact, no rounding.
    let k_int = k as i64;
    if k_int < -1022 || k_int > 1023 { return er; } // shouldn't happen given clamp above
    let scale_bits = ((k_int + 1023) as u64) << 52;
    let scale = f64::from_bits(scale_bits);
    er * scale
}
