// =============================================================================
// VEILOS: NT system services for VEILOS's own ntdll.dll (WIN32_DESIGN.md)
// =============================================================================
//
// The numbers and structure layouts are shared with ntdll through the
// `nt_abi` crate. Arguments 1-4 arrive in registers (r10 copied to the first
// argument, rdx, r8, r9); the rest are read from the caller's stack with
// `interrupts::syscall_stack_arg`. Every service returns an NTSTATUS.
//
// Waiting services (console reads, delays, object waits) give the CPU to
// other threads while they wait and end the process if it's killed meanwhile.

use alloc::sync::Arc;
use alloc::vec::Vec;
use nt_abi::{status, sys, IoStatusBlock, NtStatus, CURRENT_PROCESS};

use crate::interrupts::syscall_stack_arg as stack;
use crate::nt_file::ptr_ok;
use crate::nt_objects::KernelObjectRef;
use crate::process::Process;

/// True for the syscall numbers this module serves.
pub fn handles(id: u64) -> bool {
    (sys::BASE as u64..sys::END as u64).contains(&id)
}

pub fn dispatch(id: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let Some(proc) = crate::process::PROCESSOR.lock().get_active() else {
        return ret(status::INVALID_HANDLE);
    };
    let s = match id as u32 {
        sys::NT_TERMINATE_PROCESS => terminate_process(&proc, a0, a1 as NtStatus),
        sys::NT_WRITE_FILE => io(&proc, a0, true),
        sys::NT_READ_FILE => io(&proc, a0, false),
        sys::NT_CLOSE => close(&proc, a0),
        sys::NT_DELAY_EXECUTION => delay_execution(a1),
        sys::NT_ALLOCATE_VIRTUAL_MEMORY => allocate_vm(&proc, a0, a1, a3),
        sys::NT_FREE_VIRTUAL_MEMORY => free_vm(&proc, a0, a1, a2, a3),
        sys::NT_ALLOCATE_VIRTUAL_MEMORY_EX => allocate_vm_ex(&proc, a0, a1, a2, a3),
        sys::NT_PROTECT_VIRTUAL_MEMORY => protect_vm(&proc, a0, a1, a2, a3),
        sys::NT_QUERY_VIRTUAL_MEMORY => query_vm(&proc, a0, a1, a2, a3),
        sys::NT_CREATE_FILE => {
            let r = crate::nt_file::create_file(&proc, a0, a1, a2, a3);
            trace_name(&proc, "open", a2, r);
            r
        }
        sys::NT_QUERY_INFORMATION_FILE => {
            let class = stack(4).unwrap_or(0) as u32;
            let r = match crate::nt_ipc::pipe_query(&proc, a0, a1, a2, a3 as u32 as usize, class) {
                Some(r) => r,
                None => with_file(&proc, a0, |f| crate::nt_file::query_information(f, a1, a2, a3 as u32 as usize, class)),
            };
            if proc.trace_syscalls.load(core::sync::atomic::Ordering::Relaxed) {
                crate::serial_println!("[FILE] pid {}: query {:#x} class {} -> {:#x}", proc.pid, a0, class, r as u32);
            }
            r
        }
        sys::NT_SET_INFORMATION_FILE => with_file(&proc, a0, |f| {
            crate::nt_file::set_information(f, a1, a2, a3 as u32 as usize, stack(4).unwrap_or(0) as u32)
        }),
        sys::NT_QUERY_DIRECTORY_FILE => with_file(&proc, a0, crate::nt_file::query_directory),
        sys::NT_QUERY_ATTRIBUTES_FILE => {
            let r = crate::nt_file::query_attributes(a0, a1);
            trace_name(&proc, "attributes", a0, r);
            r
        }
        sys::NT_DELETE_FILE => crate::nt_file::delete(a0),
        sys::NT_FLUSH_BUFFERS_FILE => with_file(&proc, a0, |f| crate::nt_file::flush(f, a1)),
        sys::NT_CREATE_EVENT => crate::nt_ipc::create_event(&proc, a0, a1, a2, a3, stack(4).unwrap_or(0)),
        sys::NT_SET_EVENT => set_event(&proc, a0, a1, true),
        sys::NT_RESET_EVENT => set_event(&proc, a0, a1, false),
        sys::NT_WAIT_FOR_SINGLE_OBJECT => crate::nt_process::wait_single(&proc, a0, a2),
        sys::NT_WAIT_FOR_MULTIPLE_OBJECTS => crate::nt_process::wait_multiple(&proc, a0, a1, a2),
        sys::NT_TERMINATE_THREAD => crate::nt_process::terminate_thread(&proc, a0, a1),
        sys::NT_QUERY_INFORMATION_PROCESS => crate::nt_process::query_process(&proc, a0, a1, a2, a3),
        sys::NT_READ_VIRTUAL_MEMORY => crate::nt_process::read_memory(&proc, a0, a1, a2, a3),
        sys::NT_WRITE_VIRTUAL_MEMORY => crate::nt_section::write_memory(&proc, a0, a1, a2, a3),
        sys::NT_CREATE_SECTION => crate::nt_section::create_section(&proc, a0, a1, a2, a3),
        sys::NT_MAP_VIEW_OF_SECTION => crate::nt_section::map_view(&proc, a0, a1, a2),
        sys::NT_UNMAP_VIEW_OF_SECTION => crate::nt_section::unmap_view(&proc, a0, a1),
        sys::NT_CREATE_MUTANT => crate::nt_ipc::create_mutant(&proc, a0, a1, a2, a3),
        sys::NT_CREATE_DIRECTORY_OBJECT => crate::nt_ipc::create_directory(&proc, a0, a1, a2),
        sys::NT_OPEN_EVENT => crate::nt_ipc::open_by_attrs(&proc, a0, a1, a2, crate::nt_ipc::KIND_EVENT),
        sys::NT_OPEN_MUTANT => crate::nt_ipc::open_by_attrs(&proc, a0, a1, a2, crate::nt_ipc::KIND_MUTEX),
        sys::NT_OPEN_SEMAPHORE => crate::nt_ipc::open_by_attrs(&proc, a0, a1, a2, crate::nt_ipc::KIND_SEMAPHORE),
        sys::NT_OPEN_SECTION => crate::nt_ipc::open_by_attrs(&proc, a0, a1, a2, crate::nt_ipc::KIND_SECTION),
        sys::NT_OPEN_DIRECTORY_OBJECT => crate::nt_ipc::open_by_attrs(&proc, a0, a1, a2, crate::nt_ipc::KIND_DIRECTORY),
        sys::NT_QUERY_EVENT => crate::nt_ipc::query_event(&proc, a0, a1, a2, a3, stack(4).unwrap_or(0)),
        sys::NT_QUERY_SEMAPHORE => crate::nt_ipc::query_semaphore(&proc, a0, a1, a2, a3, stack(4).unwrap_or(0)),
        sys::NT_CREATE_TIMER => crate::nt_ipc::create_timer(&proc, a0, a1, a2, a3),
        sys::NT_SET_TIMER => crate::nt_ipc::set_timer(&proc, a0, a1),
        sys::NT_CANCEL_TIMER => crate::nt_ipc::cancel_timer(&proc, a0, a1),
        sys::NT_CREATE_SYMBOLIC_LINK_OBJECT => crate::nt_ipc::create_link(&proc, a0, a1, a2, a3),
        sys::NT_OPEN_SYMBOLIC_LINK_OBJECT => crate::nt_ipc::open_by_attrs(&proc, a0, a1, a2, crate::nt_ipc::KIND_LINK),
        sys::NT_QUERY_SYMBOLIC_LINK_OBJECT => crate::nt_ipc::query_link(&proc, a0, a1, a2),
        sys::NT_QUERY_TIMER => crate::nt_ipc::query_timer(&proc, a0, a1, a2, a3, stack(4).unwrap_or(0)),
        sys::NT_QUERY_INFORMATION_THREAD => crate::nt_process::query_thread(&proc, a0, a1, a2, a3),
        sys::NT_RESUME_THREAD => crate::nt_process::resume_thread(&proc, a0, a1),
        sys::NT_DUPLICATE_OBJECT => crate::nt_process::duplicate(&proc, a0, a1, a2, a3),
        sys::NT_OPEN_PROCESS => crate::nt_process::open_process(&proc, a0, a2, a3),
        sys::VEIL_SOCKET => crate::nt_socket::call(&proc, a0, a1, a2, a3),
        sys::VEIL_CONSOLE => crate::nt_console::call(&proc, a0, a1, a2, a3),
        sys::VEIL_CREATE_THREAD => crate::nt_process::create_thread(&proc, a0, a1, a2, a3),
        sys::VEIL_CREATE_PROCESS => crate::nt_process::create_process(&proc, a0, a1),
        sys::VEIL_CREATE_PIPE => crate::nt_process::create_pipe(&proc, a0, a1, a2),
        sys::NT_QUERY_VOLUME_INFORMATION_FILE => crate::nt_process::query_volume(&proc, a0, a1, a2, a3),
        sys::NT_SET_INFORMATION_OBJECT => {
            // ObjectHandleFlagInformation { Inherit: u8, ProtectFromClose: u8 }
            if a1 as u32 != 4 || (a3 as u32) < 2 || !ptr_ok(a2, 2) {
                status::INVALID_PARAMETER
            } else {
                let inherit = unsafe { *(a2 as *const u8) } != 0;
                match u32::try_from(a0) {
                    Ok(h) if proc.handles.lock().set_inheritable(h, inherit) => status::SUCCESS,
                    _ => status::INVALID_HANDLE,
                }
            }
        }
        sys::NT_CREATE_SEMAPHORE => {
            crate::nt_ipc::create_semaphore(&proc, a0, a1, a2, a3 as u32 as i32, stack(4).unwrap_or(1) as u32 as i32)
        }
        sys::NT_RELEASE_SEMAPHORE => match object(&proc, a0) {
            Some(KernelObjectRef::Semaphore(sem)) => match sem.release(a1 as u32 as i32) {
                Ok(prev) => {
                    if ptr_ok(a2, 4) {
                        unsafe { *(a2 as *mut i32) = prev };
                    }
                    status::SUCCESS
                }
                // STATUS_SEMAPHORE_LIMIT_EXCEEDED
                Err(_) => 0xC000_0047u32 as i32,
            },
            _ => status::INVALID_HANDLE,
        },
        sys::NT_QUERY_OBJECT => {
            if a1 as u32 != 4 || (a3 as u32) < 2 || !ptr_ok(a2, 2) {
                status::INVALID_PARAMETER
            } else {
                match u32::try_from(a0).ok().and_then(|h| proc.handles.lock().inheritable(h)) {
                    Some(inherit) => {
                        unsafe {
                            *(a2 as *mut u8) = inherit as u8;
                            *((a2 + 1) as *mut u8) = 0;
                        }
                        status::SUCCESS
                    }
                    None => status::INVALID_HANDLE,
                }
            }
        }
        sys::VEIL_DEBUG_PRINT => {
            let n = (a1 as usize).min(1024);
            if ptr_ok(a0, n) {
                let text = unsafe { core::slice::from_raw_parts(a0 as *const u8, n) };
                crate::serial_println!("[DEBUG {}] {}", proc.pid, alloc::string::String::from_utf8_lossy(text).trim_end());
            }
            status::SUCCESS
        }
        sys::NT_YIELD_EXECUTION => {
            if crate::kthread::others_ready() {
                crate::kthread::yield_now();
            }
            status::SUCCESS
        }
        sys::VEIL_USER_CREATE_WINDOW => crate::nt_user::create_window(proc.pid as u32, a0, a1),
        sys::VEIL_USER_DESTROY_WINDOW => crate::nt_user::destroy_window(a0),
        sys::VEIL_USER_SHOW_WINDOW => crate::nt_user::show_window(a0, a1),
        sys::VEIL_USER_SET_TEXT => crate::nt_user::set_text(a0, a1),
        sys::VEIL_USER_SET_POS => crate::nt_user::set_pos(a0, a1, a2),
        sys::VEIL_USER_GET_POS => crate::nt_user::get_pos(a0, a1),
        sys::VEIL_USER_PRESENT => crate::nt_user::present(a0, a1, a2, a3),
        sys::VEIL_USER_POST => crate::nt_user::post(a0, a1, a2, a3),
        sys::VEIL_USER_GET_MESSAGE => crate::nt_user::get_message(a0, a1, a2, a3),
        sys::VEIL_USER_TIMER => crate::nt_user::timer(a0, a1, a2),
        sys::VEIL_USER_QUERY => crate::nt_user::query(a0, a1),
        sys::VEIL_CLIP_SET => crate::nt_user::clip_set(proc.pid as u32, a0, a1),
        sys::VEIL_CLIP_GET => crate::nt_user::clip_get(proc.pid as u32, a0, a1, a2),
        sys::VEIL_REG => crate::nt_registry::call(proc.pid as u32, a0),
        sys::VEIL_MAP_VIEW => map_view(&proc, a0, a1, a2, a3),
        sys::VEIL_NAME_OBJECT => crate::nt_ipc::name_object(&proc, a0, a1, a2),
        sys::VEIL_OPEN_NAMED => crate::nt_ipc::open_named(&proc, a0, a1, a2),
        sys::VEIL_WAIT_ADDRESS => crate::nt_ipc::wait_address(a0, a1, a2, a3),
        sys::VEIL_WAKE_ADDRESS => crate::nt_ipc::wake_address(a0),
        sys::VEIL_PIPE => crate::nt_ipc::pipe_call(&proc, a0, a1, a2, a3),
        sys::VEIL_MUTEX => crate::nt_ipc::mutex_call(&proc, a0, a1, a2),
        sys::VEIL_SYSINFO => crate::nt_ipc::sys_info(a0, a1, a2),
        sys::VEIL_UNMAP_VIEW => unmap_view(&proc, a0),
        sys::VEIL_LOAD_DLL => load_dll(&proc, a0, a1, a2, a3),
        sys::VEIL_GET_PROC_ADDRESS => get_proc_address(&proc, a0, a1, a2),
        _ => status::NOT_IMPLEMENTED,
    };
    ret(s)
}

/// NTSTATUS in rax: the 32-bit value, zero-extended.
fn ret(s: NtStatus) -> u64 {
    s as u32 as u64
}

/// The kernel's u64 status codes (nt_memory) as NTSTATUS.
fn st(e: u64) -> NtStatus {
    e as u32 as NtStatus
}

/// NtTerminateProcess(ProcessHandle, ExitStatus): this process (all its
/// threads stop) or another one it has a handle to.
fn terminate_process(proc: &Arc<Process>, handle: u64, exit_status: NtStatus) -> NtStatus {
    if handle != CURRENT_PROCESS {
        return match object(proc, handle) {
            Some(KernelObjectRef::Process(p)) if p.pid != proc.pid => {
                crate::serial_println!("[NT] pid {} ends pid {} with code {}", proc.pid, p.pid, exit_status);
                crate::nt_process::kill_process(&p, exit_status);
                status::SUCCESS
            }
            Some(KernelObjectRef::Process(_)) => terminate_process(proc, CURRENT_PROCESS, exit_status),
            Some(_) => status::OBJECT_TYPE_MISMATCH,
            None => status::INVALID_HANDLE,
        };
    }
    crate::serial_println!("[NT] pid {} exits with code {}", proc.pid, exit_status);
    crate::nt_process::kill_process(proc, exit_status);
    unsafe { crate::loader::return_from_usermode() }
}

/// The object a handle refers to.
fn object(proc: &Process, handle: u64) -> Option<KernelObjectRef> {
    let h = u32::try_from(handle).ok()?;
    proc.handles.lock().get_ref(h).cloned()
}

fn with_file(proc: &Process, handle: u64, f: impl FnOnce(&crate::nt_file::FileObject) -> NtStatus) -> NtStatus {
    match object(proc, handle) {
        Some(KernelObjectRef::File(file)) => f(&file),
        Some(_) => status::OBJECT_TYPE_MISMATCH,
        None => status::INVALID_HANDLE,
    }
}

/// NtReadFile / NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
/// IoStatusBlock, Buffer, Length, ByteOffset, Key). Synchronous.
fn io(proc: &Process, handle: u64, writing: bool) -> NtStatus {
    // Stack arguments first: the per-CPU user RSP they're read through is
    // another thread's once this one waits.
    let (Some(iosb), Some(buffer), Some(length)) = (stack(4), stack(5), stack(6)) else {
        return status::ACCESS_VIOLATION;
    };
    let offset = stack(7).unwrap_or(0);
    let length = length as u32 as usize;
    if !ptr_ok(buffer, length) || !ptr_ok(iosb, core::mem::size_of::<IoStatusBlock>()) {
        return status::ACCESS_VIOLATION;
    }
    if writing && proc.trace_syscalls.load(core::sync::atomic::Ordering::Relaxed) {
        let at = if ptr_ok(offset, 8) { unsafe { *(offset as *const i64) } } else { -99 };
        let n = length.min(40);
        let text: alloc::string::String = unsafe { core::slice::from_raw_parts(buffer as *const u8, n) }
            .iter().map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' }).collect();
        crate::serial_println!("[IO] pid {}: write {:#x} {} bytes at {} {:?}", proc.pid, handle, length, at, text);
    }
    match object(proc, handle) {
        Some(KernelObjectRef::File(f)) if writing => crate::nt_file::write(&f, iosb, buffer, length, offset),
        Some(KernelObjectRef::File(f)) => crate::nt_file::read(&f, iosb, buffer, length, offset),
        Some(KernelObjectRef::Null) => {
            let (s, n) = if writing { (status::SUCCESS, length) } else { (status::END_OF_FILE, 0) };
            unsafe { *(iosb as *mut IoStatusBlock) = IoStatusBlock { status: s as u32 as u64, information: n as u64 } };
            s
        }
        Some(KernelObjectRef::Duplex(end)) => {
            let (s, n) = end.io(buffer, length, writing);
            unsafe { *(iosb as *mut IoStatusBlock) = IoStatusBlock { status: s as u32 as u64, information: n as u64 } };
            s
        }
        Some(KernelObjectRef::Pipe(end)) => {
            let (s, n) = crate::nt_process::pipe_io(&end, buffer, length, writing);
            unsafe { *(iosb as *mut IoStatusBlock) = IoStatusBlock { status: s as u32 as u64, information: n as u64 } };
            s
        }
        Some(KernelObjectRef::ConsoleBuffer(b)) if writing => {
            let data = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) }.to_vec();
            b.write_utf8(&data);
            unsafe { *(iosb as *mut IoStatusBlock) = IoStatusBlock { status: 0, information: length as u64 } };
            status::SUCCESS
        }
        Some(KernelObjectRef::ConsoleBuffer(_)) => 0xC000_0010u32 as NtStatus, // STATUS_INVALID_DEVICE_REQUEST
        Some(KernelObjectRef::Console(console)) if writing => {
            let data = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) }.to_vec();
            console.write(&data);
            unsafe { *(iosb as *mut IoStatusBlock) = IoStatusBlock { status: 0, information: length as u64 } };
            status::SUCCESS
        }
        Some(KernelObjectRef::Console(console)) => {
            if length == 0 {
                return status::SUCCESS;
            }
            // Text as the input mode gives it (a line, or what's typed), as
            // UTF-8: at most a third as many units as bytes, so it fits.
            let units = loop {
                if let Some(text) = console.read_text((length / 3).max(1)) {
                    break text;
                }
                if !console.is_live() {
                    return status::END_OF_FILE;
                }
                crate::loader::kill_if_requested();
                wait_a_little();
            };
            let data = alloc::string::String::from_utf16_lossy(&units);
            let n = data.len().min(length);
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), buffer as *mut u8, n);
                *(iosb as *mut IoStatusBlock) = IoStatusBlock { status: 0, information: n as u64 };
            }
            status::SUCCESS
        }
        Some(_) => status::OBJECT_TYPE_MISMATCH,
        None => status::INVALID_HANDLE,
    }
}

/// A timeout argument (LARGE_INTEGER*, 100 ns units: negative = relative,
/// positive = absolute system time) as a TICKS deadline; None = forever.
pub fn deadline(timeout: u64) -> Option<u64> {
    if timeout == 0 || !ptr_ok(timeout, 8) {
        return None;
    }
    let t = unsafe { core::ptr::read_unaligned(timeout as *const i64) };
    let now = crate::interrupts::TICKS.load(core::sync::atomic::Ordering::Relaxed);
    Some(if t < 0 { now + (t.unsigned_abs() / 10_000) } else { now }) // absolute times: not used yet
}

/// NtDelayExecution(Alertable, DelayInterval*).
fn delay_execution(interval: u64) -> NtStatus {
    let Some(until) = deadline(interval) else { return status::ACCESS_VIOLATION };
    if until <= crate::interrupts::TICKS.load(core::sync::atomic::Ordering::Relaxed) {
        // Sleep(0): give up the rest of the slice.
        if crate::kthread::others_ready() {
            crate::kthread::yield_now();
        }
        return status::SUCCESS;
    }
    while crate::interrupts::TICKS.load(core::sync::atomic::Ordering::Relaxed) < until {
        crate::loader::kill_if_requested();
        wait_a_little();
    }
    status::SUCCESS
}

/// Inside a syscall (interrupts off, no locks held): let other threads run,
/// or sleep until the next interrupt if there are none.
/// Says so in the log when a blocking call has gone on a long time, with what
/// it's waiting for and the program's likely return addresses. Made before
/// waiting: the user stack pointer it reads belongs to another thread after.
pub struct WaitNote {
    what: &'static str,
    rsp: u64,
    next_ms: u64,
    every_ms: u64,
}

impl WaitNote {
    pub fn new(what: &'static str) -> Self {
        Self { what, rsp: crate::smp::current_syscall_user_rsp(), next_ms: crate::time::now_ms() + 15_000, every_ms: 30_000 }
    }

    pub fn tick(&mut self) {
        let now = crate::time::now_ms();
        if now < self.next_ms {
            return;
        }
        self.next_ms = now + self.every_ms;
        self.every_ms = self.every_ms.saturating_mul(2);
        let mut trail = alloc::string::String::new();
        for i in 0..256 {
            let at = self.rsp + i * 8;
            if !crate::memory::user_ptr_ok(at, 8) {
                break;
            }
            let v = unsafe { *(at as *const u64) };
            if (0x1_4000_0000..0x1_5000_0000).contains(&v) || (0x2_0000_0000..0x3_0000_0000).contains(&v) {
                trail.push_str(&alloc::format!(" {:#x}", v));
            }
        }
        crate::serial_println!("[WAIT] pid {} still in {}:{}", crate::kthread::current_pid(), self.what, trail);
    }
}

pub fn wait_a_little() {
    if crate::kthread::others_ready() {
        crate::kthread::yield_now();
    } else {
        // A timer interrupt in ring 0 never switches threads, so this only
        // pauses until it (or a keystroke) arrives.
        x86_64::instructions::interrupts::enable_and_hlt();
        x86_64::instructions::interrupts::disable();
    }
}

/// NtClose(Handle). Closing a file's last handle writes it back.
fn close(proc: &Process, handle: u64) -> NtStatus {
    match u32::try_from(handle) {
        Ok(h) if proc.handles.lock().close(h) => status::SUCCESS,
        _ => status::INVALID_HANDLE,
    }
}

// -----| virtual memory |-----

fn read_u64(p: u64) -> Option<u64> {
    ptr_ok(p, 8).then(|| unsafe { core::ptr::read_unaligned(p as *const u64) })
}

fn write_u64(p: u64, v: u64) {
    if ptr_ok(p, 8) {
        unsafe { core::ptr::write_unaligned(p as *mut u64, v) };
    }
}

/// The process a memory call is about: this one, or another by handle
/// (Cygwin's fork prepares its child's memory). Its work runs with that
/// process's address space loaded; the caller's own pointers are read and
/// written outside it.
fn vm_target(proc: &Arc<Process>, h: u64) -> Option<Arc<Process>> {
    match crate::nt_process::object_or_self(proc, h)? {
        KernelObjectRef::Process(p) => Some(p),
        _ => None,
    }
}

/// NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, ZeroBits,
/// RegionSize*, AllocationType, Protect).
fn allocate_vm(proc: &Arc<Process>, h: u64, base_ptr: u64, size_ptr: u64) -> NtStatus {
    let Some(target) = vm_target(proc, h) else { return status::INVALID_HANDLE };
    let (Some(alloc_type), Some(protect)) = (stack(4), stack(5)) else { return status::ACCESS_VIOLATION };
    let (Some(base), Some(size)) = (read_u64(base_ptr), read_u64(size_ptr)) else { return status::ACCESS_VIOLATION };
    let r = crate::address_space::with(target.cr3, || target.vad.lock().virtual_alloc(base, size as usize, alloc_type as u32, protect as u32));
    if proc.trace_syscalls.load(core::sync::atomic::Ordering::Relaxed) {
        crate::serial_println!("[VM] pid {}: alloc {:#x}+{:#x} type {:#x} protect {:#x} -> {:x?}", target.pid, base, size, alloc_type, protect, r);
    }
    match r {
        Ok(addr) => {
            let end = (base.max(addr) + size + 0xFFF) & !0xFFF;
            write_u64(base_ptr, addr);
            write_u64(size_ptr, end - addr);
            status::SUCCESS
        }
        Err(e) => st(e),
    }
}

/// NtAllocateVirtualMemoryEx(process, base*, size*, type, protect, params*,
/// count): MemExtendedParameterAddressRequirements says where (the lowest
/// and highest address, and the alignment); other parameters aren't kept.
fn allocate_vm_ex(proc: &Arc<Process>, h: u64, base_ptr: u64, size_ptr: u64, alloc_type: u64) -> NtStatus {
    const MEM_TOP_DOWN: u32 = 0x10_0000;
    const REQUIREMENTS: u64 = 1;
    let Some(target) = vm_target(proc, h) else { return status::INVALID_HANDLE };
    let (Some(protect), Some(params), Some(count)) = (stack(4), stack(5), stack(6)) else { return status::ACCESS_VIOLATION };
    let (protect, alloc_type, count) = (protect as u32, alloc_type as u32, count as u32 as usize);
    let (Some(mut base), Some(size)) = (read_u64(base_ptr), read_u64(size_ptr)) else { return status::ACCESS_VIOLATION };
    if count > 16 || (count != 0 && !ptr_ok(params, count * 16)) {
        return status::INVALID_PARAMETER;
    }
    let mut wanted = None;
    for i in 0..count as u64 {
        // MEM_EXTENDED_PARAMETER: its type in the low 8 bits, then a pointer or value.
        let (kind, value) = unsafe {
            (core::ptr::read_unaligned((params + i * 16) as *const u64) & 0xFF, core::ptr::read_unaligned((params + i * 16 + 8) as *const u64))
        };
        if kind == REQUIREMENTS {
            if !ptr_ok(value, 24) {
                return status::ACCESS_VIOLATION;
            }
            wanted = Some(unsafe {
                (core::ptr::read_unaligned(value as *const u64), core::ptr::read_unaligned((value + 8) as *const u64), core::ptr::read_unaligned((value + 16) as *const u64))
            });
        }
    }
    let r = crate::address_space::with(target.cr3, || {
        let mut vad = target.vad.lock();
        if let (0, Some((low, high, align))) = (base, wanted) {
            match vad.find_free_within(low, high, align, size as usize, alloc_type & MEM_TOP_DOWN != 0) {
                Some(at) => base = at,
                None => return Err(status::NO_MEMORY as u32 as u64),
            }
        }
        vad.virtual_alloc(base, size as usize, alloc_type, protect)
    });
    if proc.trace_syscalls.load(core::sync::atomic::Ordering::Relaxed) {
        crate::serial_println!("[VM] pid {}: alloc-ex {:#x}+{:#x} type {:#x} protect {:#x} wanted {:x?} -> {:x?}", target.pid, base, size, alloc_type, protect, wanted, r);
    }
    match r {
        Ok(addr) => {
            let end = (base.max(addr) + size + 0xFFF) & !0xFFF;
            write_u64(base_ptr, addr);
            write_u64(size_ptr, end - addr);
            status::SUCCESS
        }
        Err(e) => st(e),
    }
}

/// NtFreeVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*, FreeType).
fn free_vm(proc: &Arc<Process>, h: u64, base_ptr: u64, size_ptr: u64, free_type: u64) -> NtStatus {
    let Some(target) = vm_target(proc, h) else { return status::INVALID_HANDLE };
    let (Some(base), Some(size)) = (read_u64(base_ptr), read_u64(size_ptr)) else { return status::ACCESS_VIOLATION };
    let r = crate::address_space::with(target.cr3, || target.vad.lock().virtual_free(base, size as usize, free_type as u32));
    if proc.trace_syscalls.load(core::sync::atomic::Ordering::Relaxed) {
        crate::serial_println!("[VM] pid {}: free {:#x}+{:#x} type {:#x} -> {:x?}", target.pid, base, size, free_type, r);
    }
    match r {
        Ok(()) => status::SUCCESS,
        Err(e) => st(e),
    }
}

/// NtProtectVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*,
/// NewProtect, OldProtect*).
/// For a traced process: the object name an OBJECT_ATTRIBUTES gives, and what came of it.
fn trace_name(proc: &Process, what: &str, oa: u64, r: NtStatus) {
    if proc.trace_syscalls.load(core::sync::atomic::Ordering::Relaxed) {
        let name = crate::nt_file::read_object_name(oa).unwrap_or_default();
        crate::serial_println!("[FILE] pid {}: {} {:?} -> {:#x}", proc.pid, what, name, r as u32);
    }
}

/// VEIL_MAP_VIEW(file, offset, size, flags | out*): flags on the stack.
fn map_view(proc: &Process, file: u64, offset: u64, size: u64, out: u64) -> NtStatus {
    let flags = stack(4).unwrap_or(0);
    if !ptr_ok(out, 8) || size == 0 || offset & 0xFFF != 0 {
        return if ptr_ok(out, 8) { status::INVALID_PARAMETER } else { status::ACCESS_VIOLATION };
    }
    let shared = match proc.handles.lock().get_ref(file as u32) {
        Some(KernelObjectRef::File(f)) => f.shared(),
        _ => None,
    };
    let Some(shared) = shared else { return status::INVALID_HANDLE };
    let Some(base) = proc.vad.lock().reserve_view(size as usize) else { return status::NO_MEMORY };
    crate::nt_demand::add_view(base, size, shared, offset, flags & 1 != 0, flags & 2 != 0);
    unsafe { *(out as *mut u64) = base };
    status::SUCCESS
}

/// VEIL_UNMAP_VIEW(addr): not one of these views if it fails.
fn unmap_view(proc: &Process, addr: u64) -> NtStatus {
    match crate::nt_demand::remove_view(addr) {
        Some((base, _)) => {
            proc.vad.lock().forget(base);
            status::SUCCESS
        }
        None => status::INVALID_PARAMETER,
    }
}

fn protect_vm(proc: &Arc<Process>, h: u64, base_ptr: u64, size_ptr: u64, new: u64) -> NtStatus {
    let Some(target) = vm_target(proc, h) else { return status::INVALID_HANDLE };
    let old_ptr = stack(4).unwrap_or(0);
    let (Some(base), Some(size)) = (read_u64(base_ptr), read_u64(size_ptr)) else { return status::ACCESS_VIOLATION };
    let r = crate::address_space::with(target.cr3, || {
        // Pages not read from their file yet would lose the new protection.
        crate::nt_demand::fault_range(base, size);
        target.vad.lock().virtual_protect(base, size as usize, new as u32)
    });
    if proc.trace_syscalls.load(core::sync::atomic::Ordering::Relaxed) {
        crate::serial_println!("[VM] pid {}: protect {:#x}+{:#x} to {:#x} -> {:x?}", target.pid, base, size, new, r);
    }
    match r {
        Ok(old) => {
            if ptr_ok(old_ptr, 4) {
                unsafe { *(old_ptr as *mut u32) = old };
            }
            status::SUCCESS
        }
        Err(e) => st(e),
    }
}

/// NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
/// MemoryInformation*, Length, ReturnLength*): MemoryBasicInformation only.
fn query_vm(proc: &Arc<Process>, h: u64, addr: u64, class: u64, out: u64) -> NtStatus {
    let Some(target) = vm_target(proc, h) else { return status::INVALID_HANDLE };
    let (length, ret_len) = (stack(4).unwrap_or(0) as usize, stack(5).unwrap_or(0));
    if class != 0 {
        return status::INVALID_INFO_CLASS;
    }
    if length < 48 {
        return status::BUFFER_TOO_SMALL;
    }
    if !ptr_ok(out, 48) {
        return status::ACCESS_VIOLATION;
    }
    let m = crate::address_space::with(target.cr3, || target.vad.lock().virtual_query(addr));
    unsafe {
        let p = out as *mut u8;
        core::ptr::write_bytes(p, 0, 48);
        core::ptr::write_unaligned(p as *mut u64, m.base_address);
        core::ptr::write_unaligned(p.add(8) as *mut u64, m.allocation_base);
        core::ptr::write_unaligned(p.add(16) as *mut u32, m.allocation_protect);
        core::ptr::write_unaligned(p.add(24) as *mut u64, m.region_size as u64);
        core::ptr::write_unaligned(p.add(32) as *mut u32, m.state);
        core::ptr::write_unaligned(p.add(36) as *mut u32, m.protect);
        core::ptr::write_unaligned(p.add(40) as *mut u32, m.region_type);
    }
    write_u64(ret_len, 48);
    status::SUCCESS
}

// -----| events and waits |-----

/// NtCreateEvent(EventHandle*, DesiredAccess, ObjectAttributes*, EventType
/// (0 = manual reset, 1 = auto reset), InitialState). Names are ignored.
/// NtSetEvent / NtResetEvent(EventHandle, PreviousState*).
fn set_event(proc: &Process, h: u64, prev: u64, set: bool) -> NtStatus {
    let Some(KernelObjectRef::Event(ev)) = object(proc, h) else { return status::INVALID_HANDLE };
    let was = ev.signaled.load(core::sync::atomic::Ordering::Acquire);
    if set { ev.set() } else { ev.reset() }
    if ptr_ok(prev, 4) {
        unsafe { *(prev as *mut i32) = was as i32 };
    }
    status::SUCCESS
}

// -----| run-time loading |-----

/// VEIL_LOAD_DLL(name*, name_chars, base_out*, inits*, inits_capacity, count_out*).
fn load_dll(proc: &Process, name: u64, chars: u64, base_out: u64, inits: u64) -> NtStatus {
    let (Some(capacity), Some(count_out)) = (stack(4), stack(5)) else { return status::ACCESS_VIOLATION };
    let chars = chars as usize;
    if chars == 0 || chars > 520 || !ptr_ok(name, chars * 2) || !ptr_ok(base_out, 8) || !ptr_ok(count_out, 4) {
        return status::ACCESS_VIOLATION;
    }
    let units = unsafe { core::slice::from_raw_parts(name as *const u16, chars) };
    let name: alloc::string::String = char::decode_utf16(units.iter().copied()).map(|c| c.unwrap_or('?')).collect();
    let mut linker = proc.linker.lock();
    let Some(linker) = linker.as_mut() else { return status::DLL_NOT_FOUND };
    let mut mapper = unsafe { crate::memory::get_mapper() };
    let mut fa = crate::memory::GlobalFrameAllocator;
    let mut pages = proc.mapped_pages.lock();
    let mut mem = crate::modules::Mem { mapper: &mut mapper, fa: &mut fa, pages: &mut pages };
    // What the process already uses, so a DLL's preferred base isn't taken over it.
    linker.taken = proc.vad.lock().ranges();
    let (base, calls) = match linker.load_at_runtime(&mut mem, &name) {
        Ok(r) => r,
        Err(s) => {
            crate::serial_println!("[MODULES] pid {}: LoadLibrary({}) failed: {:#x}", proc.pid, name, s as u32);
            return s;
        }
    };
    // The initial loader snapshots linker.unresolved into process.unresolved_imports.
    // A later LoadLibrary may create more unresolved stubs, with syscall IDs
    // indexed into the growing linker.unresolved vector. Keep the process's
    // names in sync so those IDs do not show up as "an unknown function".
    // Only append: old entries retain their "already logged" state.
    {
        let mut unresolved = proc.unresolved_imports.lock();
        let previous = unresolved.len();
        if linker.unresolved.len() > previous {
            unresolved.extend(linker.unresolved[previous..].iter().cloned().map(|name| (name, false)));
            crate::serial_println!(
                "[MODULES] pid {}: LoadLibrary({}) registered {} more unresolved import(s) (total {})",
                proc.pid, name, unresolved.len() - previous, unresolved.len()
            );
        }
    }
    let n = calls.len().min(capacity as usize);
    if n > 0 && !ptr_ok(inits, n * core::mem::size_of::<nt_abi::InitCall>()) {
        return status::ACCESS_VIOLATION;
    }
    for (i, (routine, module)) in calls.iter().take(n).enumerate() {
        unsafe { *((inits as *mut nt_abi::InitCall).add(i)) = nt_abi::InitCall { routine: *routine, module: *module } };
    }
    unsafe {
        *(base_out as *mut u64) = base;
        *(count_out as *mut u32) = n as u32;
    }
    // VirtualAlloc must not hand out what was just mapped.
    let mut vad = proc.vad.lock();
    for (b, s) in linker.regions() {
        if vad.is_free(b, s) {
            vad.record_image(b, s);
        }
    }
    status::SUCCESS
}

/// VEIL_GET_PROC_ADDRESS(module_base, name* or ordinal, address_out*).
fn get_proc_address(proc: &Process, base: u64, name: u64, out: u64) -> NtStatus {
    if !ptr_ok(out, 8) {
        return status::ACCESS_VIOLATION;
    }
    let symbol = if name < 0x10000 {
        None
    } else {
        match crate::memory::user_cstr_len(name, 256) {
            Some(n) => Some(alloc::string::String::from_utf8_lossy(unsafe { core::slice::from_raw_parts(name as *const u8, n) }).into_owned()),
            None => return status::ACCESS_VIOLATION,
        }
    };
    let mut linker = proc.linker.lock();
    let Some(linker) = linker.as_mut() else { return status::PROCEDURE_NOT_FOUND };
    let mut mapper = unsafe { crate::memory::get_mapper() };
    let mut fa = crate::memory::GlobalFrameAllocator;
    let mut pages = proc.mapped_pages.lock();
    let mut mem = crate::modules::Mem { mapper: &mut mapper, fa: &mut fa, pages: &mut pages };
    match linker.proc_address(&mut mem, base, symbol.as_deref(), name as u16) {
        Some(addr) => {
            if proc.trace_syscalls.load(core::sync::atomic::Ordering::Relaxed) {
                crate::serial_println!("[MODULES] pid {}: GetProcAddress({:#x}, {}) = {:#x}", proc.pid, base, symbol.as_deref().unwrap_or("#"), addr);
            }
            unsafe { *(out as *mut u64) = addr };
            status::SUCCESS
        }
        None => {
            // Rare, and the name is what's needed to add it.
            crate::serial_println!(
                "[MODULES] pid {}: GetProcAddress({:#x}, {}) not found",
                proc.pid, base, symbol.as_deref().map_or(alloc::format!("#{}", name), |s| alloc::string::String::from(s))
            );
            status::PROCEDURE_NOT_FOUND
        }
    }
}
