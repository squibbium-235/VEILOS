// =====================================================================
// smp.rs — Symmetric Multi-Processing bootstrap
// =====================================================================
//
// Responsibilities:
//   1.  Discover how many logical CPUs the firmware reported (via CPUID).
//   2.  Identify the Local APIC base address and map it.
//   3.  For each Application Processor (AP, i.e. every CPU except core 0),
//       send the standard INIT → SIPI → SIPI startup sequence.
//   4.  Each AP executes `ap_entry()` which:
//         a) loads its own per-CPU GDT + TSS (unique stacks)
//         b) loads the shared IDT
//         c) enables its Local APIC and sets the timer vector
//         d) enables SYSCALL/SYSRET
//         e) parks in a lightweight run-loop ready for work
//
// ── Limitations & future work ─────────────────────────────────────────
// • AP scheduling: APs currently idle-halt.  The scheduler's SchedDomain
//   will be extended to N domains (one per CPU) in a follow-up.
// • CPU discovery: ACPI MADT is parsed for an authoritative CPU count and
//   the real APIC ID of each processor (see `parse_madt`).
//   CPUID leaf 0x1 EBX[23:16] is kept only as a fallback for the rare case
//   the MADT can't be found/parsed — that field is unreliable under some
//   hypervisors (notably it can reflect the host's topology rather than the
//   guest's requested `-smp N` under WHPX), which is why relying on it alone
//   previously reported "1 CPU" even when more were requested.
// • 16-bit trampoline: real hardware — and real QEMU, on every accelerator —
//   always starts an AP in 16-bit real mode after SIPI, regardless of the
//   guest CPU model string. There is no "start directly in long mode"
//   special case for `qemu64`. A previous version of this file assumed one
//   existed and pointed SIPI directly at `ap_entry` (a 64-bit function) with
//   no real-mode code ever placed at the SIPI vector — every AP jumped into
//   effectively-zeroed low memory and never came up, which is the actual
//   reason only the BSP ever appeared online. `AP_TRAMPOLINE` below is a
//   real, self-relocating 16→32→64-bit bootstrap copied to a fixed low page
//   before any SIPI is sent.

use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::VirtAddr;
use x86_64::structures::paging::{
    Page, PhysFrame, Size4KiB, FrameAllocator, PageTableFlags, Mapper,
};
use x86_64::PhysAddr;

// ── LAPIC register offsets (relative to LAPIC base) ──────────────────
const LAPIC_ID:            usize = 0x020; // Local APIC ID
const LAPIC_EOI:           usize = 0x0B0; // End-of-interrupt
const LAPIC_SVR:           usize = 0x0F0; // Spurious vector register
const LAPIC_ICR_LOW:       usize = 0x300; // Interrupt Command Register (low)
const LAPIC_ICR_HIGH:      usize = 0x310; // Interrupt Command Register (high)
const LAPIC_TIMER_LVT:     usize = 0x320; // Timer LVT entry
const LAPIC_TIMER_INITIAL: usize = 0x380; // Timer initial count
const LAPIC_TIMER_CURRENT: usize = 0x390; // Timer current count
const LAPIC_TIMER_DIVIDE:  usize = 0x3E0; // Timer divide config

/// Number of logical CPUs detected at runtime.
pub static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// LAPIC virtual base address (set once during init, read-only thereafter).
pub static LAPIC_BASE: AtomicU32 = AtomicU32::new(0);

/// Bitmask: bit N is set when CPU N has completed its AP startup sequence.
pub static CPU_ONLINE: AtomicU32 = AtomicU32::new(1); // BSP (core 0) always online

// ── Per-CPU data ───────────────────────────────────────────────────────
//
// Each logical CPU owns one `PerCpu` block. `KERNEL_GS_BASE` points at it,
// so `syscall_entry` reaches it with `swapgs` + `gs:[offset]` without
// touching any general-purpose register or the (untrusted) user stack.
//
// Other kernel code must NOT use `gs:` to find its CPU: an interrupt that
// arrives in ring 3 does not `swapgs`, so GS still holds the user's TEB
// there. Use `cpu_index()` (LAPIC-ID lookup) instead.
//
// Each CPU also gets a dedicated 64 KiB syscall stack. It is used ONLY for
// syscalls — never as a boot or idle stack (APs get separate boot stacks
// in `init`). Sharing the two used to let the first syscall on an AP
// overwrite the frames `return_from_usermode()` later jumps back into.

pub const SYSCALL_STACK_SIZE: usize = 4096 * 16;   // 64 KiB per CPU
pub const MAX_CPUS:           usize = 8;            // supports up to 8-way SMP

/// Size of each AP's boot/idle stack (heap-allocated in `init`).
const AP_BOOT_STACK_SIZE: usize = 4096 * 16;

/// Byte offsets into `PerCpu`, used by the naked `syscall_entry` asm.
pub const PERCPU_KERNEL_RSP: usize = 0;
pub const PERCPU_USER_RSP:   usize = 8;

#[repr(C, align(64))]
pub struct PerCpu {
    /// Top of this CPU's syscall stack. Offset 0 (`PERCPU_KERNEL_RSP`).
    pub kernel_rsp: u64,
    /// User RSP saved by `syscall_entry` for the syscall in progress.
    /// Offset 8 (`PERCPU_USER_RSP`).
    pub user_rsp: u64,
    pub cpu_index: u64,
    pub apic_id: u64,
}

#[repr(C, align(16))]
struct SyscallStack([u8; SYSCALL_STACK_SIZE]);

// Both tables are written through raw pointers (by `init_percpu`, and by
// the CPU itself when it uses a stack), so they need interior mutability.
// A plain immutable `static` written this way is UB and may even be placed
// in read-only memory.
struct PerCpuTable(core::cell::UnsafeCell<[PerCpu; MAX_CPUS]>);
unsafe impl Sync for PerCpuTable {}
struct StackTable(core::cell::UnsafeCell<[SyscallStack; MAX_CPUS]>);
unsafe impl Sync for StackTable {}

static PERCPU: PerCpuTable = PerCpuTable(core::cell::UnsafeCell::new(
    [const { PerCpu { kernel_rsp: 0, user_rsp: 0, cpu_index: 0, apic_id: 0 } }; MAX_CPUS]
));
static SYSCALL_STACKS: StackTable = StackTable(core::cell::UnsafeCell::new(
    [const { SyscallStack([0u8; SYSCALL_STACK_SIZE]) }; MAX_CPUS]
));

/// APIC ID → CPU index. 0xFF = unknown. APIC IDs are not dense on real
/// hardware (e.g. 0, 2, 4, ... or > MAX_CPUS), so they can't index tables
/// directly.
static APIC_TO_CPU: [core::sync::atomic::AtomicU8; 256] =
    [const { core::sync::atomic::AtomicU8::new(0xFF) }; 256];

fn percpu_ptr(cpu_index: usize) -> *mut PerCpu {
    unsafe { (*PERCPU.0.get()).as_mut_ptr().add(cpu_index) }
}

/// Top (high address) of `cpu_index`'s syscall stack.
fn syscall_stack_top(cpu_index: usize) -> u64 {
    let base = unsafe { (*SYSCALL_STACKS.0.get())[cpu_index].0.as_ptr() } as u64;
    base + SYSCALL_STACK_SIZE as u64
}

fn write_kernel_gs_base(value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC0000102u32,  // MSR_KERNEL_GS_BASE
            in("eax") (value & 0xFFFF_FFFF) as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }
}

/// Address of `cpu`'s per-CPU block (what KERNEL_GS_BASE holds outside a
/// syscall).
pub fn percpu_base(cpu: usize) -> u64 {
    percpu_ptr(cpu) as u64
}

/// The stack `syscall_entry` switches to on `cpu`. The scheduler points it at
/// the kernel stack of the user thread it switches to (kthread).
pub fn set_syscall_stack(cpu: usize, top: u64) {
    unsafe { (*percpu_ptr(cpu)).kernel_rsp = top };
}

/// Set up the calling CPU's `PerCpu` block and point `KERNEL_GS_BASE` at it.
/// Must run on the CPU being initialised (called from `gdt::init`/`init_ap`).
pub fn init_percpu(cpu_index: usize) {
    assert!(cpu_index < MAX_CPUS, "CPU index out of range");
    let apic_id = current_apic_id();
    let p = percpu_ptr(cpu_index);
    unsafe {
        (*p).kernel_rsp = syscall_stack_top(cpu_index);
        (*p).user_rsp   = 0;
        (*p).cpu_index  = cpu_index as u64;
        (*p).apic_id    = apic_id as u64;
    }
    APIC_TO_CPU[(apic_id & 0xFF) as usize].store(cpu_index as u8, Ordering::Release);
    write_kernel_gs_base(p as u64);
    crate::serial_println!(
        "[SMP] CPU {} (APIC ID {}) per-CPU block at {:#x}, syscall stack top {:#x}",
        cpu_index, apic_id, p as u64, syscall_stack_top(cpu_index)
    );
}

/// Enable SSE/SSE2 on the calling CPU. CR4/CR0 are per-CPU registers, so
/// every CPU must run this — an AP without it raises #UD on the first SSE
/// instruction (e.g. the XMM save in `syscall_entry`, or MSVC code zeroing a
/// struct with XORPS).
///   • CR4.OSFXSR (bit 9): allow SSE + FXSAVE/FXRSTOR.
///   • CR4.OSXMMEXCPT (bit 10): deliver SIMD FP faults as #XM.
///   • CR0.EM (bit 2) clear: no x87 emulation; CR0.TS (bit 3) clear: no #NM.
pub fn enable_sse() {
    unsafe {
        core::arch::asm!(
            "mov rax, cr4",
            "or  rax, {cr4_bits}",
            "mov cr4, rax",
            "mov rax, cr0",
            "and rax, {cr0_mask}",
            "mov cr0, rax",
            cr4_bits = const (1u64 << 9) | (1u64 << 10),
            cr0_mask = const !((1u64 << 2) | (1u64 << 3)),
            out("rax") _,
            options(nostack),
        );
        core::arch::asm!("fninit", options(nostack, nomem));
    }
    enable_xsave_query();
}

/// CR4.OSXSAVE (bit 18), where the CPU has XSAVE, with XCR0 = x87 + SSE:
/// the state the kernel already saves with FXSAVE. Programs may then ask
/// with XGETBV which state the OS manages (Cygwin's signal code does, and
/// XGETBV is #UD without OSXSAVE); AVX stays off, so they don't use it.
fn enable_xsave_query() {
    let ecx = unsafe { core::arch::x86_64::__cpuid(1) }.ecx;
    if ecx & (1 << 26) == 0 {
        return; // no XSAVE
    }
    unsafe {
        core::arch::asm!(
            "mov rax, cr4",
            "or  rax, {bit}",
            "mov cr4, rax",
            "xor ecx, ecx",
            "mov eax, 3",
            "xor edx, edx",
            "xsetbv",
            bit = const 1u64 << 18,
            out("rax") _, out("rcx") _, out("rdx") _,
            options(nostack),
        );
    }
}

/// IA32_PAT with entry 1 changed from write-through to write-combining:
///   PA0 WB, PA1 WC, PA2 UC-, PA3 UC, PA4 WB, PA5 WT, PA6 UC-, PA7 UC.
/// A 4 KiB PTE with only PWT (`PageTableFlags::WRITE_THROUGH`) set therefore
/// maps write-combining, which is what framebuffers and VRAM want: writes
/// are batched into bursts instead of one bus transaction per pixel (UC).
/// PCD|PWT still selects UC for MMIO registers. Nothing in the kernel wanted
/// plain write-through, and NT's PAGE_WRITECOMBINE already set PWT alone.
const PAT_VALUE: u64 = 0x0007_0406_0007_0106;

/// Program the PAT. Per-CPU state, and every CPU must use the same value, so
/// call it on the BSP before any WC mapping exists and on each AP at bring-up.
pub fn init_pat() {
    use core::arch::x86_64::__cpuid;
    if unsafe { __cpuid(1) }.edx & (1 << 16) == 0 {
        crate::serial_println!("[PAT] CPU has no PAT; WRITE_THROUGH mappings stay write-through");
        return;
    }
    unsafe {
        x86_64::registers::model_specific::Msr::new(0x277).write(PAT_VALUE);
        // SDM: flush caches and TLBs after changing memory types.
        core::arch::asm!("wbinvd", options(nostack));
    }
    x86_64::instructions::tlb::flush_all();
}

/// Re-point `KERNEL_GS_BASE` at this CPU's block. Called before every ring-3
/// launch: a long-jump out of a syscall (`return_from_usermode`) skips the
/// exit `swapgs`, leaving the user TEB in `KERNEL_GS_BASE`.
pub fn reset_kernel_gs_base() {
    write_kernel_gs_base(percpu_ptr(cpu_index()) as u64);
}

/// Index (0..MAX_CPUS) of the CPU executing this code. Safe from any context,
/// including interrupt handlers that interrupted ring 3.
#[inline]
pub fn cpu_index() -> usize {
    let idx = APIC_TO_CPU[(current_apic_id() & 0xFF) as usize].load(Ordering::Relaxed);
    if idx == 0xFF { 0 } else { idx as usize }
}

/// User RSP of the syscall currently executing on this CPU.
pub fn current_syscall_user_rsp() -> u64 {
    unsafe { (*percpu_ptr(cpu_index())).user_rsp }
}

// ── LAPIC access ──────────────────────────────────────────────────────

/// Read a 32-bit LAPIC register at `offset` bytes from the LAPIC base.
#[inline(always)]
unsafe fn lapic_read(offset: usize) -> u32 {
    let base = LAPIC_BASE.load(Ordering::Relaxed) as usize;
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Write a 32-bit value to a LAPIC register.
#[inline(always)]
unsafe fn lapic_write(offset: usize, val: u32) {
    let base = LAPIC_BASE.load(Ordering::Relaxed) as usize;
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val); }
}

/// Read the APIC ID from CPUID leaf 1, EBX[31:24].
/// rbx is reserved by LLVM so we spill it manually around cpuid.
fn cpuid_apic_id() -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "mov {out:e}, ebx",
            "pop rbx",
            out = out(reg) result,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack),
        );
    }
    (result >> 24) & 0xFF
}

/// Read the current CPU's APIC ID from LAPIC register 0x20.
#[inline(always)]
pub fn current_apic_id() -> u32 {
    if LAPIC_BASE.load(Ordering::Relaxed) == 0 {
        cpuid_apic_id()
    } else {
        unsafe { lapic_read(LAPIC_ID) >> 24 }
    }
}

/// LAPIC timer counts per millisecond at divide-by-16, measured on the BSP by
/// `calibrate_lapic_timer`. Every LAPIC timer in the system runs off the same
/// bus/crystal clock, so APs use the BSP's figure.
static LAPIC_TICKS_PER_MS: AtomicU32 = AtomicU32::new(0);

/// Count used if calibration fails: the old hard-coded value.
const LAPIC_TICKS_PER_MS_FALLBACK: u32 = 0x40000;

/// LAPIC timer divide-configuration value for divide-by-16.
const LAPIC_DIVIDE_16: u32 = 0x3;

/// LAPIC timer counts per millisecond (divide-by-16), for programming
/// periodic or one-shot timers.
pub fn lapic_timer_ticks_per_ms() -> u32 {
    match LAPIC_TICKS_PER_MS.load(Ordering::Relaxed) {
        0 => LAPIC_TICKS_PER_MS_FALLBACK,
        n => n,
    }
}

/// Measure the LAPIC timer rate against PIT channel 2. The BSP's LAPIC must
/// be mapped and enabled.
fn calibrate_lapic_timer() {
    let rate = unsafe {
        lapic_write(LAPIC_TIMER_DIVIDE, LAPIC_DIVIDE_16);
        // Masked one-shot: count down from the top, raise nothing.
        lapic_write(LAPIC_TIMER_LVT, (1 << 16) | crate::interrupts::AP_TIMER_VECTOR as u32);
        lapic_write(LAPIC_TIMER_INITIAL, u32::MAX);
        let rate = crate::time::calibrate(|| (u32::MAX - lapic_read(LAPIC_TIMER_CURRENT)) as u64);
        lapic_write(LAPIC_TIMER_INITIAL, 0); // stop
        rate
    };
    match rate.map(|hz| hz / 1_000).filter(|&per_ms| per_ms > 0 && per_ms <= u32::MAX as u64) {
        Some(per_ms) => {
            LAPIC_TICKS_PER_MS.store(per_ms as u32, Ordering::Relaxed);
            crate::serial_println!(
                "[SMP] LAPIC timer: {} ticks/ms at divide-by-16 ({} kHz bus)",
                per_ms, per_ms * 16
            );
        }
        None => crate::serial_println!(
            "[SMP] WARN: LAPIC timer calibration failed; using {:#x} ticks/ms",
            LAPIC_TICKS_PER_MS_FALLBACK
        ),
    }
}

/// Send a write to LAPIC ICR.  Waits for the Delivery Status bit to clear
/// (i.e. the IPI has been accepted by the bus) before returning.
unsafe fn lapic_send_ipi(apic_id: u8, delivery: u32) {
    unsafe {
        lapic_write(LAPIC_ICR_HIGH, (apic_id as u32) << 24);
        lapic_write(LAPIC_ICR_LOW,  delivery);
        // Spin until Delivery Status (bit 12) clears.
        let mut timeout = 1_000_000u32;
        while (lapic_read(LAPIC_ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
            timeout -= 1;
            if timeout == 0 {
                crate::serial_println!("[SMP] IPI delivery timeout for APIC ID {}", apic_id);
                break;
            }
        }
    }
}

// ── LAPIC discovery & mapping ─────────────────────────────────────────

/// Read the IA32_APIC_BASE MSR to get the physical base of the LAPIC.
fn read_lapic_phys_base_proper() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") 0x1Bu32,
            out("eax") lo,
            out("edx") hi,
        );
    }
    let full = ((hi as u64) << 32) | (lo as u64);
    full & 0xFFFF_FFFF_F000u64
}

// =====================================================================
// -----| Real-mode -> protected-mode -> long-mode AP trampoline |-----
// =====================================================================
//
// Pre-assembled x86 machine code blob for the AP startup trampoline.
//
// The blob is hand-encoded rather than produced by global_asm! because
// Rust's global_asm! on Windows uses the MSVC toolchain assembler (MASM),
// which does not understand GAS/AT&T directives (.code16, .quad, .org, etc.).
// The encoded bytes are identical to what a GAS invocation would produce.
//
// Layout (all offsets relative to the copy at AP_TRAMPOLINE_PHYS = 0x8000):
//   0x000  16-bit real-mode entry (SIPI lands here)
//   0x080  GDT: null(8) + code32(8) + data32(8) + code64(8)
//   0x0A0  GDTR (6 bytes: word limit + dword base, base patched at runtime)
//   0x0B0  PM far-jump ptr (dword offset + word selector, offset patched)
//   0x0C0  parameter block (written by write_ap_params before every SIPI):
//            +0x00 cr3 (u64), +0x08 entry (u64), +0x10 stack_top (u64),
//            +0x18 cpu_index (u32), +0x1C padding (u32)
//   0x0E0  LM far-jump ptr (dword offset + word selector, offset patched)
//   0x100  32-bit protected-mode code
//   0x180  64-bit long-mode code
//
// NOTE: the real-mode far jump at 0x04A MUST carry the 0x66 operand-size prefix
// (66 67 FF AE B0 00 00 00 = ljmpl *0xB0(%esi)). Without it the CPU reads a
// m16:16 pointer, takes selector 0x0000 from the high half of the offset,
// and triple-faults (QEMU then resets the whole VM -> boot loop).
// NOTE: the 32-bit stage writes EFER with LME *and* NXE (or eax,0x900). The kernel's
// page tables (built by bootloader 0.9) mark .data/.bss/.rodata NO_EXECUTE and the
// bootloader only enables EFER.NXE on the BSP. An AP that enables paging with NXE=0
// takes a reserved-bit #PF on the first NX-marked entry it touches (its own stack),
// and with no IDT yet that triple-faults. The 64-bit stub also does `sub rsp, 8`
// before `jmp rax` so ap_entry sees the SysV-expected RSP % 16 == 8.
// NOTE: GDT descriptor byte order is limit[15:0], base[23:0], ACCESS (byte 5), FLAGS|limit[19:16]
// (byte 6), base[31:24]. i.e. flat 32-bit code = FF FF 00 00 00 9A CF 00 (NOT ... CF 9A ...).
// To regenerate: tools/assemble_trampoline.py (requires Python).
#[allow(clippy::all)]
static AP_TRAMPOLINE_BYTES: [u8; 0x200] = [
    /* 0x000 */ 0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0xBC, 0xF0, 0x0F, 0x8C, 0xC8, 0x66, 0x0F,
    /* 0x010 */ 0xB7, 0xF0, 0x66, 0xC1, 0xE6, 0x04, 0x67, 0x66, 0x8D, 0x86, 0x80, 0x00, 0x00, 0x00, 0x67, 0x66,
    /* 0x020 */ 0x89, 0x86, 0xA2, 0x00, 0x00, 0x00, 0x67, 0x66, 0x8D, 0x86, 0x00, 0x01, 0x00, 0x00, 0x67, 0x66,
    /* 0x030 */ 0x89, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x67, 0x0F, 0x01, 0x96, 0xA0, 0x00, 0x00, 0x00, 0x66, 0x0F,
    /* 0x040 */ 0x20, 0xC0, 0x66, 0x83, 0xC8, 0x01, 0x66, 0x0F, 0x22, 0xC0, 0x66, 0x67, 0xFF, 0xAE, 0xB0, 0x00,
    /* 0x050 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x060 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x070 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x080 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00,
    /* 0x090 */ 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xAF, 0x00,
    /* 0x0a0 */ 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x0b0 */ 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x0c0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x0d0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x0e0 */ 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x0f0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x100 */ 0x66, 0xB8, 0x10, 0x00, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xE0, 0x8E, 0xE8, 0x8E, 0xD0, 0xBC, 0xF0,
    /* 0x110 */ 0x0F, 0x00, 0x00, 0x0F, 0x20, 0xE0, 0x83, 0xC8, 0x20, 0x0F, 0x22, 0xE0, 0x8B, 0x86, 0xC0, 0x00,
    /* 0x120 */ 0x00, 0x00, 0x0F, 0x22, 0xD8, 0xB9, 0x80, 0x00, 0x00, 0xC0, 0x0F, 0x32, 0x0D, 0x00, 0x09, 0x00,
    /* 0x130 */ 0x00, 0x0F, 0x30, 0x0F, 0x20, 0xC0, 0x0D, 0x00, 0x00, 0x00, 0x80, 0x0F, 0x22, 0xC0, 0x8D, 0x86,
    /* 0x140 */ 0x80, 0x01, 0x00, 0x00, 0x89, 0x86, 0xE0, 0x00, 0x00, 0x00, 0xFF, 0xAE, 0xE0, 0x00, 0x00, 0x00,
    /* 0x150 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x160 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x170 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x180 */ 0x48, 0x89, 0xF3, 0x48, 0x8B, 0x83, 0xC8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xA3, 0xD0, 0x00, 0x00,
    /* 0x190 */ 0x00, 0x8B, 0xBB, 0xD8, 0x00, 0x00, 0x00, 0x66, 0xB9, 0x10, 0x00, 0x8E, 0xD9, 0x8E, 0xC1, 0x8E,
    /* 0x1a0 */ 0xE1, 0x8E, 0xE9, 0x8E, 0xD1, 0x48, 0x83, 0xEC, 0x08, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x1b0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x1c0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x1d0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x1e0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* 0x1f0 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Size of the trampoline page we install (full 4 KiB, zero-padded after the blob).
const AP_TRAMPOLINE_SIZE: usize = 4096;

/// Physical address the trampoline is copied to (must match SIPI vector 0x08 -> 0x8000).
const AP_TRAMPOLINE_PHYS: u64 = 0x8000;

const AP_TR_PARAMS_OFF: u64 = 0x0C0;

/// Copy the trampoline blob to its fixed physical address and identity-map the page.
fn install_ap_trampoline(mapper: &mut impl Mapper<Size4KiB>, frame_allocator: &mut impl FrameAllocator<Size4KiB>) {
    unsafe {
        core::ptr::copy_nonoverlapping(
            AP_TRAMPOLINE_BYTES.as_ptr(),
            AP_TRAMPOLINE_PHYS as *mut u8,
            AP_TRAMPOLINE_BYTES.len(),
        );
        core::ptr::write_bytes(
            (AP_TRAMPOLINE_PHYS as *mut u8).add(AP_TRAMPOLINE_BYTES.len()),
            0u8,
            AP_TRAMPOLINE_SIZE - AP_TRAMPOLINE_BYTES.len(),
        );
    }

    let page  = Page::<Size4KiB>::containing_address(VirtAddr::new(AP_TRAMPOLINE_PHYS));
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(AP_TRAMPOLINE_PHYS));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    unsafe {
        match mapper.map_to(page, frame, flags, frame_allocator) {
            Ok(tlb) => tlb.flush(),
            Err(_)  => {}
        }
    }
    crate::serial_println!("[SMP] AP trampoline installed at {:#X}", AP_TRAMPOLINE_PHYS);
    crate::serial_println!("[SMP] trampoline check: rm-ljmp={:02X?} efer-or={:02X?}",
        unsafe { core::slice::from_raw_parts((AP_TRAMPOLINE_PHYS + 0x4A) as *const u8, 8) },
        unsafe { core::slice::from_raw_parts((AP_TRAMPOLINE_PHYS + 0x12C) as *const u8, 5) });
}


/// Write this AP's launch parameters into the live trampoline copy.
/// Called once per AP, immediately before sending its SIPI — APs are
/// brought up strictly one at a time (the caller waits for CPU_ONLINE
/// before moving to the next), so reusing the same parameter block is safe.
fn write_ap_params(cpu_index: u32, stack_top: u64) {
    use x86_64::registers::control::Cr3;
    let (cr3_frame, _) = Cr3::read();
    let cr3 = cr3_frame.start_address().as_u64();
    debug_assert!(cr3 < (1u64 << 32), "kernel CR3 must be below 4GiB for the 32-bit trampoline stage");

    let entry = ap_entry as *const () as u64;
    let base = (AP_TRAMPOLINE_PHYS + AP_TR_PARAMS_OFF) as *mut u8;
    unsafe {
        core::ptr::write_unaligned(base.add(0x00) as *mut u64, cr3);
        core::ptr::write_unaligned(base.add(0x08) as *mut u64, entry);
        core::ptr::write_unaligned(base.add(0x10) as *mut u64, stack_top);
        core::ptr::write_unaligned(base.add(0x18) as *mut u32, cpu_index);
    }
}

/// Detect if we are running under Hyper-V (which includes WHPX on Windows).
///
/// Hyper-V advertises itself via CPUID leaf 0x40000000:
///   EBX:ECX:EDX = b"Microsoft Hv" (little-endian, 4 bytes each)
/// When this is detected, the 16-bit AP real-mode trampoline cannot be used
/// because WHPX does not support executing 16-bit guest code.
fn running_under_hyper_v() -> bool {
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 0x40000000",
            "cpuid",
            "mov {ebx:e}, ebx",
            "pop rbx",
            ebx = out(reg) ebx,
            out("eax") _,
            out("ecx") ecx,
            out("edx") edx,
            options(nostack),
        );
    }
    // "Microsoft Hv" as three little-endian u32s:
    //   EBX = 0x7263694D  ('M','i','c','r')
    //   ECX = 0x666F736F  ('o','s','o','f')
    //   EDX = 0x76482074  ('t',' ','H','v')
    ebx == 0x7263694D && ecx == 0x666F736F && edx == 0x76482074
}

fn cpuid_logical_cpu_count() -> u32 {
    let ebx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "mov {out:e}, ebx",
            "pop rbx",
            out = out(reg) ebx,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack),
        );
    }
    let count = (ebx >> 16) & 0xFF;
    if count == 0 { 1 } else { count.min(MAX_CPUS as u32) }
}

// =====================================================================
// -----| ACPI MADT discovery |-----
// =====================================================================
//
// The MADT (Multiple APIC Description Table) is the authoritative,
// firmware/hypervisor-provided list of every logical processor and its real
// APIC ID. Unlike CPUID leaf 1's topology field, QEMU always populates the
// MADT correctly according to `-smp N` regardless of which accelerator
// (tcg, kvm, whpx, hvf) is backing the guest, because it's a static table
// built at VM construction time rather than something that has to be
// virtualized per-instruction.

/// An I/O APIC entry (MADT type 1).
#[derive(Clone, Copy, Debug)]
pub struct MadtIoApic {
    pub id:       u8,
    pub address:  u32,
    pub gsi_base: u32,
}

/// An interrupt source override (MADT type 2): ISA IRQ `source` arrives on
/// `gsi` with the given MPS INTI polarity/trigger `flags`.
#[derive(Clone, Copy, Debug)]
pub struct MadtOverride {
    pub bus:    u8,
    pub source: u8,
    pub gsi:    u32,
    pub flags:  u16,
}

/// What the kernel uses from the MADT.
pub struct Madt {
    /// APIC ID of every enabled processor.
    pub apic_ids:  alloc::vec::Vec<u8>,
    pub ioapics:   alloc::vec::Vec<MadtIoApic>,
    pub overrides: alloc::vec::Vec<MadtOverride>,
}

/// Read `len` bytes from physical memory via the bootloader's physical
/// memory mapping (`map_physical_memory`), which covers all of low memory
/// and any ACPI tables the firmware reports.
unsafe fn read_phys<T: Copy>(phys_addr: u64) -> T {
    let virt = crate::memory::get_phys_mem_offset().as_u64() + phys_addr;
    unsafe { core::ptr::read_unaligned(virt as *const T) }
}

unsafe fn read_phys_bytes(phys_addr: u64, len: usize) -> &'static [u8] {
    let virt = crate::memory::get_phys_mem_offset().as_u64() + phys_addr;
    unsafe { core::slice::from_raw_parts(virt as *const u8, len) }
}

/// Locate the RSDP by scanning the two regions the ACPI spec guarantees it
/// lives in on a BIOS boot: the first 1 KiB of the Extended BIOS Data Area,
/// and the BIOS read-only memory space 0xE0000–0xFFFFF. Both are scanned on
/// 16-byte boundaries for the 8-byte signature "RSD PTR ".
fn find_rsdp() -> Option<u64> {
    const SIG: &[u8; 8] = b"RSD PTR ";

    let checksum_ok = |addr: u64, len: usize| -> bool {
        let bytes = unsafe { read_phys_bytes(addr, len) };
        bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
    };

    let scan = |start: u64, end: u64| -> Option<u64> {
        let mut addr = start;
        while addr + 8 <= end {
            let sig = unsafe { read_phys_bytes(addr, 8) };
            if sig == SIG && checksum_ok(addr, 20) {
                return Some(addr);
            }
            addr += 16;
        }
        None
    };

    // EBDA base is a real-mode segment stored as a u16 at physical 0x40E.
    let ebda_seg: u16 = unsafe { read_phys(0x40E) };
    let ebda_base = (ebda_seg as u64) << 4;
    if ebda_base != 0 {
        if let Some(a) = scan(ebda_base, ebda_base + 1024) { return Some(a); }
    }
    scan(0xE0000, 0x100000)
}

/// Parse the MADT (signature "APIC") reachable from the RSDP: the APIC ID of
/// every enabled processor, plus the I/O APICs and ISA interrupt overrides.
/// Returns `None` if there is no MADT or it lists no enabled processor.
pub fn parse_madt() -> Option<Madt> {
    let rsdp_addr = find_rsdp()?;

    let revision: u8 = unsafe { read_phys(rsdp_addr + 15) };

    // ACPI 2.0+: prefer the XSDT (64-bit pointers) when present and valid.
    let (sdt_addr, entry_size, is_xsdt): (u64, usize, bool) = if revision >= 2 {
        let xsdt_addr: u64 = unsafe { read_phys(rsdp_addr + 24) };
        if xsdt_addr != 0 { (xsdt_addr, 8, true) }
        else {
            let rsdt_addr: u32 = unsafe { read_phys(rsdp_addr + 16) };
            (rsdt_addr as u64, 4, false)
        }
    } else {
        let rsdt_addr: u32 = unsafe { read_phys(rsdp_addr + 16) };
        (rsdt_addr as u64, 4, false)
    };
    if sdt_addr == 0 { return None; }

    // Standard ACPI SDT header: sig[4] len[4] rev[1] checksum[1] oem_id[6]
    // oem_table_id[8] oem_rev[4] creator_id[4] creator_rev[4] = 36 bytes.
    let sdt_len: u32 = unsafe { read_phys(sdt_addr + 4) };
    if (sdt_len as usize) < 36 { return None; }
    let entry_count = (sdt_len as usize - 36) / entry_size;

    let mut madt_addr: Option<u64> = None;
    for i in 0..entry_count {
        let ptr_addr = sdt_addr + 36 + (i * entry_size) as u64;
        let table_addr: u64 = if is_xsdt {
            unsafe { read_phys::<u64>(ptr_addr) }
        } else {
            unsafe { read_phys::<u32>(ptr_addr) as u64 }
        };
        if table_addr == 0 { continue; }
        let sig = unsafe { read_phys_bytes(table_addr, 4) };
        if sig == b"APIC" {
            madt_addr = Some(table_addr);
            break;
        }
    }
    let madt_addr = madt_addr?;

    let madt_len: u32 = unsafe { read_phys(madt_addr + 4) };
    if (madt_len as usize) < 44 { return None; }

    let mut apic_ids = alloc::vec::Vec::new();
    let mut ioapics = alloc::vec::Vec::new();
    let mut overrides = alloc::vec::Vec::new();
    let mut offset: u64 = madt_addr + 44; // past header + local_apic_addr + flags
    let end: u64 = madt_addr + madt_len as u64;

    while offset + 2 <= end {
        let entry_type: u8 = unsafe { read_phys(offset) };
        let entry_len: u8  = unsafe { read_phys(offset + 1) };
        if entry_len < 2 { break; } // malformed — avoid an infinite loop

        if entry_type == 0 && entry_len as u64 >= 8 {
            // Processor Local APIC: acpi_id[1] apic_id[1] flags[4]
            let apic_id: u8 = unsafe { read_phys(offset + 3) };
            let flags: u32  = unsafe { read_phys(offset + 4) };
            const ENABLED: u32 = 1 << 0;
            if flags & ENABLED != 0 {
                apic_ids.push(apic_id);
            }
        } else if entry_type == 1 && entry_len as u64 >= 12 {
            // I/O APIC: id[1] reserved[1] address[4] gsi_base[4]
            ioapics.push(MadtIoApic {
                id:       unsafe { read_phys(offset + 2) },
                address:  unsafe { read_phys(offset + 4) },
                gsi_base: unsafe { read_phys(offset + 8) },
            });
        } else if entry_type == 2 && entry_len as u64 >= 10 {
            // Interrupt source override: bus[1] source[1] gsi[4] flags[2]
            overrides.push(MadtOverride {
                bus:    unsafe { read_phys(offset + 2) },
                source: unsafe { read_phys(offset + 3) },
                gsi:    unsafe { read_phys(offset + 4) },
                flags:  unsafe { read_phys(offset + 8) },
            });
        }
        // Type 9 (Local x2APIC) exists for >255 CPUs; out of scope for the
        // MAX_CPUS=8 cap this kernel currently supports.

        offset += entry_len as u64;
    }

    if apic_ids.is_empty() { None } else { Some(Madt { apic_ids, ioapics, overrides }) }
}

// ── AP entry point ─────────────────────────────────────────────────────

/// A Windows process queued for an AP. The AP looks the process up by pid and
/// runs it with `loader::spawn_user_thread`, the same path the BSP uses
/// (entry point, stack and page tables all come from the `Process`).
pub struct ApWorkItem {
    /// A Windows thread to start: process `pid`'s thread `tid`.
    pub pid: u32,
    pub tid: u32,
}

pub static AP_WORK_QUEUE: spin::Mutex<alloc::vec::Vec<ApWorkItem>> = spin::Mutex::new(alloc::vec::Vec::new());

/// How many user-process threads each CPU runs. A CPU can run any number
/// (kthread switches between them); APs take new processes least-loaded first.
pub static USER_THREADS: [core::sync::atomic::AtomicU32; MAX_CPUS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MAX_CPUS];

/// True if no online AP runs fewer user threads than `cpu`.
fn least_loaded_ap(cpu: usize) -> bool {
    let online = CPU_ONLINE.load(Ordering::Acquire);
    let mine = USER_THREADS[cpu].load(Ordering::Acquire);
    (1..MAX_CPUS)
        .filter(|&c| online & (1 << c) != 0)
        .all(|c| USER_THREADS[c].load(Ordering::Acquire) >= mine)
}

/// An AP's boot thread: the CPU's worker loop (HAL step 7B).
///
/// Each pass it helps with any posted `workers::for_each` batch, starts a
/// queued Windows process on its own kernel thread if this CPU has none,
/// gives the CPU to that thread if it is waiting, and otherwise halts until
/// an interrupt: the 1 ms LAPIC tick or a wake IPI from `wake_aps`. A
/// running process is preempted back to this loop every slice (the AP timer
/// handler calls `kthread::preempt_from_timer`), so batches never wait
/// behind it for long. APs used to run one process to completion here and
/// do nothing else.
pub fn park_and_wait_for_work() -> ! {
    let cpu = cpu_index();
    loop {
        if crate::workers::help() {
            continue;
        }
        if least_loaded_ap(cpu) {
            let work = AP_WORK_QUEUE.lock().pop();
            if let Some(ApWorkItem { pid, tid }) = work {
                let process = crate::process::PROCESSOR.lock().find(pid);
                let thread = process.as_ref().and_then(|p| p.threads.lock().iter().find(|t| t.tid == tid).cloned());
                match (process, thread) {
                    (Some(process), Some(thread)) => crate::nt_process::run_thread_here(process, thread),
                    _ => crate::serial_println!("[SMP] queued thread {} of pid {} no longer exists", tid, pid),
                }
                continue;
            }
        }
        if crate::kthread::others_ready() {
            crate::kthread::yield_now();
            continue;
        }
        x86_64::instructions::interrupts::disable();
        if crate::workers::pending() || (least_loaded_ap(cpu) && !AP_WORK_QUEUE.lock().is_empty()) {
            x86_64::instructions::interrupts::enable();
        } else {
            x86_64::instructions::interrupts::enable_and_hlt();
        }
    }
}

/// Wake every other CPU from `hlt` (fixed IPI on the AP timer vector, whose
/// handler only acknowledges it). Used when work is posted for them.
pub fn wake_aps() {
    if LAPIC_BASE.load(Ordering::Relaxed) == 0 || CPU_ONLINE.load(Ordering::Acquire).count_ones() <= 1 {
        return;
    }
    // ICR: destination shorthand "all excluding self" (bits 18-19 = 11),
    // level assert, fixed delivery.
    let icr = 0x000C_4000 | crate::interrupts::AP_TIMER_VECTOR as u32;
    x86_64::instructions::interrupts::without_interrupts(|| unsafe {
        lapic_write(LAPIC_ICR_HIGH, 0);
        lapic_write(LAPIC_ICR_LOW, icr);
        let mut spins = 0u32;
        while lapic_read(LAPIC_ICR_LOW) & (1 << 12) != 0 && spins < 100_000 {
            core::hint::spin_loop();
            spins += 1;
        }
    });
}

/// Each AP jumps here after the SIPI.
///
/// At this point the AP is in 64-bit mode (QEMU qemu64 CPU) with:
///   • no GDT of its own   → we load one immediately
///   • no IDT loaded       → we load the shared IDT
///   • LAPIC enabled but timer not configured
///   • interrupts disabled (by INIT)
///
/// We keep this function `#[no_mangle]` so the SIPI target address can be
/// computed at compile time from the symbol, and `extern "C"` to get a
/// predictable calling convention when invoked from inline asm.
#[unsafe(no_mangle)]
pub extern "C" fn ap_entry(cpu_index: u32) -> ! {
    // 1. Load this AP's own GDT + TSS (unique stacks per CPU).
    //    init_ap() also calls init_percpu(cpu_index) internally.
    crate::gdt::init_ap(cpu_index as usize);

    // 2. Load the shared IDT (already built on the BSP).
    crate::interrupts::init_idt_ap();

    // 2b. SSE is per-CPU state: without this the AP #UDs on its first SSE
    //     instruction (the first syscall it handles, or the app itself).
    enable_sse();
    init_pat();

    // 3. Enable the LAPIC and configure the timer on this core.
    unsafe {
        // Spurious vector 0xFF — enables the LAPIC.
        lapic_write(LAPIC_SVR, 0x100 | 0xFF);
        // Timer: periodic, on the dedicated AP-timer vector. NOT vector 32: that is the
        // BSP's PIT handler, which bumps the global TICKS clock, runs the scheduler tick and
        // acks the legacy PIC -- and never sends a LAPIC EOI, so an AP would get exactly one
        // tick and then never wake from `hlt` again (see interrupts::AP_TIMER_VECTOR).
        lapic_write(LAPIC_TIMER_LVT,     0x20000 | crate::interrupts::AP_TIMER_VECTOR as u32); // periodic
        lapic_write(LAPIC_TIMER_DIVIDE,  LAPIC_DIVIDE_16);
        lapic_write(LAPIC_TIMER_INITIAL, lapic_timer_ticks_per_ms()); // 1 ms period
    }

    // 4. Enable SYSCALL/SYSRET on this AP using the same MSR values as the BSP.
    crate::interrupts::init_syscall_ap();

    // 5. Mark this CPU as online.
    CPU_ONLINE.fetch_or(1 << cpu_index, Ordering::Release);
    crate::serial_println!("[SMP] CPU {} online (APIC ID {})", cpu_index, current_apic_id());

    // 6. Enable interrupts and park — the scheduler will give this core work.
    unsafe { core::arch::asm!("sti"); }
    park_and_wait_for_work()
}

// ── BSP startup sequence ───────────────────────────────────────────────

/// Called from `kernel_main` after the heap, GDT, and IDT are live.
///
/// 1. Discover LAPIC base and CPU count.
/// 2. Map the LAPIC into the virtual address space.
/// 3. Enable the BSP's LAPIC.
/// 4. Send INIT + SIPI × 2 to each AP.
/// 5. Wait for all APs to check in (with a 200 ms timeout per AP).
pub fn init(
    mapper:           &mut impl Mapper<Size4KiB>,
    frame_allocator:  &mut impl FrameAllocator<Size4KiB>,
) {
    // ── 1. Discover ──────────────────────────────────────────────────────
    let lapic_phys = read_lapic_phys_base_proper();

    // Prefer the ACPI MADT: it's the firmware/hypervisor's own authoritative
    // processor list and is populated correctly by QEMU according to
    // `-smp N` regardless of accelerator. CPUID leaf 1's topology field is
    // kept only as a fallback — under some hypervisors (WHPX in particular)
    // it can reflect host topology rather than the guest's requested count,
    // which is why this previously reported "1 CPU" even when more were
    // requested on the command line.
    let madt = parse_madt();
    let (cpu_count, apic_ids): (u32, alloc::vec::Vec<u8>) = match &madt {
        Some(m) => {
            let n = (m.apic_ids.len() as u32).min(MAX_CPUS as u32);
            crate::serial_println!("[SMP] MADT reports {} enabled processor(s): {:?}", m.apic_ids.len(), m.apic_ids);
            (n, m.apic_ids.clone())
        }
        None => {
            let n = cpuid_logical_cpu_count();
            crate::serial_println!("[SMP] MADT not found/parseable — falling back to CPUID leaf 1 ({})", n);
            // Fallback assumes the common QEMU layout: sequential APIC IDs 0..N-1.
            (n, (0..n as u8).collect())
        }
    };

    crate::serial_println!("[SMP] LAPIC phys base: {:#012x}", lapic_phys);
    crate::serial_println!("[SMP] Logical CPU count: {}", cpu_count);
    crate::println!("[SMP] {} logical CPUs detected", cpu_count);

    CPU_COUNT.store(cpu_count, Ordering::Release);

    // ── 2. Map the LAPIC page ─────────────────────────────────────────────
    // The LAPIC is MMIO — it must be mapped as uncacheable (NO_CACHE).
    let lapic_virt = lapic_phys; // identity map for simplicity
    let flags = PageTableFlags::PRESENT
              | PageTableFlags::WRITABLE
              | PageTableFlags::NO_CACHE;
    {
        let phys_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(lapic_phys));
        let virt_page  = Page::<Size4KiB>::containing_address(VirtAddr::new(lapic_virt));
        unsafe {
            match mapper.map_to(virt_page, phys_frame, flags, frame_allocator) {
                Ok(tlb) => tlb.flush(),
                Err(_)  => {} // already mapped (e.g. if BIOS identity-mapped it)
            }
        }
    }
    LAPIC_BASE.store(lapic_virt as u32, Ordering::Release);

    // ── 3. Enable BSP LAPIC ───────────────────────────────────────────────
    unsafe {
        // Spurious Interrupt Vector Register: bit 8 = APIC Software Enable.
        lapic_write(LAPIC_SVR, 0x100 | 0xFF);
    }
    calibrate_lapic_timer();

    if cpu_count <= 1 {
        crate::serial_println!("[SMP] Single CPU — skipping AP startup.");
        return;
    }

    // ── WHPX / Hyper-V guard ────────────────────────────────────────────────────
    //
    // WHPX (Windows Hypervisor Platform) is built on Hyper-V and does not
    // support running guest code in 16-bit real mode. After SIPI the AP would
    // immediately take an Unrecoverable VP exit (exit code 4) and crash the VM.
    // Hyper-V identifies itself via CPUID leaf 0x40000000 returning
    // "Microsoft Hv" in EBX:ECX:EDX. When detected, skip AP startup entirely.
    if running_under_hyper_v() {
        crate::serial_println!(
            "[SMP] WARNING: Hyper-V/WHPX detected. 16-bit real-mode AP trampoline is "
        );
        crate::serial_println!(
            "[SMP]   not supported under this hypervisor. Running single-core."
        );
        crate::serial_println!(
            "[SMP]   To enable SMP: use -accel tcg,thread=multi -smp N instead of whpx."
        );
        CPU_COUNT.store(1, Ordering::Release);
        return;
    }

    // ── 4. Install the real AP trampoline ───────────────────────────────
    //
    // Every AP, on every accelerator, starts in 16-bit real mode after SIPI
    // — there is no "starts directly in long mode" special case for any
    // guest CPU model. A previous version of this code assumed one existed
    // and pointed SIPI straight at `ap_entry` (a 64-bit function) with no
    // real code ever placed at the SIPI vector; every AP jumped into
    // effectively empty low memory and silently never came up, which is why
    // only the BSP was ever online regardless of `-smp N`.
    install_ap_trampoline(mapper, frame_allocator);

    // ── 5. Start APs ──────────────────────────────────────────────────────
    //
    // The boot protocol (Intel SDM Vol.3 §8.4.4):
    //   a) INIT IPI  — resets the AP; it enters wait-for-SIPI state.
    //   b) 10 ms delay
    //   c) SIPI #1   — sends the startup vector (AP begins executing there).
    //   d) 200 µs delay
    //   e) SIPI #2   — in case #1 was missed.
    //
    // The SIPI vector byte encodes a 4 KiB-page-aligned address in the first
    // 1 MiB: real_mode_addr = vector << 12. Vector 0x08 → 0x8000, matching
    // AP_TRAMPOLINE_PHYS above.

    let bsp_apic_id = current_apic_id();

    let mut cpu_index: u32 = 0;
    for &ap_apic_id in apic_ids.iter() {
        if ap_apic_id == bsp_apic_id as u8 { continue; }
        cpu_index += 1;
        if cpu_index >= cpu_count { break; }

        crate::serial_println!("[SMP] Starting AP index {} (APIC ID {})", cpu_index, ap_apic_id);

        // Give this AP its own boot/idle stack and tell the trampoline where
        // to jump once it reaches long mode. Written fresh for each AP — they
        // come up strictly one at a time (we wait for CPU_ONLINE below
        // before touching the parameter block again).
        //
        // This must NOT be the AP's syscall stack: ap_entry and
        // park_and_wait_for_work live on this stack for the AP's whole life,
        // and launch_into_usermode saves its long-jump RSP here. The stack is
        // leaked on purpose — the AP never stops using it.
        let boot_stack: &'static mut [u8] = alloc::vec![0u8; AP_BOOT_STACK_SIZE].leak();
        let stack_top = (boot_stack.as_ptr() as u64 + AP_BOOT_STACK_SIZE as u64) & !0xF;
        write_ap_params(cpu_index, stack_top);

        unsafe {
            // a) INIT IPI
            // Delivery mode 5 (INIT), Level=Assert, all others 0.
            lapic_send_ipi(ap_apic_id, 0x0000_4500);

            // b) 10 ms delay
            crate::time::delay_ms(10);

            // c) SIPI #1 — vector byte = 0x08 (address 0x8000, where the real
            //    trampoline installed above now lives).
            lapic_send_ipi(ap_apic_id, 0x0000_4608); // delivery=STARTUP, vector=0x08

            // d) 200 µs delay
            crate::time::delay_us(200);

            // e) SIPI #2
            lapic_send_ipi(ap_apic_id, 0x0000_4608);
        }

        // ── 6. Wait for AP to come online (200 ms timeout) ────────────────
        let online = crate::time::spin_until(200_000, || {
            CPU_ONLINE.load(Ordering::Acquire) & (1 << cpu_index) != 0
        });
        if !online {
            crate::serial_println!(
                "[SMP] AP index {} (APIC ID {}) did not come online within 200 ms — skipping.",
                cpu_index, ap_apic_id
            );
            // Reduce the advertised CPU count so the scheduler doesn't
            // try to assign work to a core that never woke up.
            CPU_COUNT.fetch_sub(1, Ordering::AcqRel);
        }
    }

    let online = CPU_ONLINE.load(Ordering::Acquire).count_ones();
    crate::println!("[SMP] {}/{} CPUs online.", online, cpu_count);
    crate::serial_println!("[SMP] init complete. Online mask: {:#010b}", CPU_ONLINE.load(Ordering::Acquire));
}

/// Send an EOI to the LAPIC on the current CPU.
/// Called at the end of every hardware interrupt handler.
#[inline(always)]
pub fn lapic_eoi() {
    if LAPIC_BASE.load(Ordering::Relaxed) != 0 {
        unsafe { lapic_write(LAPIC_EOI, 0); }
    }
}
