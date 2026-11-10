//! Synchronisation primitives shared by Windows-ABI callers.
//!
//! VEILOS currently represents an SRW lock as a u64:
//! high bit = exclusive owner, otherwise the number of shared owners.
//! This is deliberately the same layout kernel32/src/sync.rs uses, so an
//! SRW lock can be acquired via either NTDLL or Kernel32.
//!
//! The one-time initialiser uses the RTL_RUN_ONCE one-pointer layout:
//! 0 = uninitialised, 1 = initialising, (context | 2) = completed.
//! Windows reserves the low two bits of a stored context pointer.

use core::sync::atomic::{AtomicU64, Ordering};
use nt_abi::{kusd, status, NtStatus};

const WRITER: u64 = 1 << 63;
const RUN_ONCE_BUSY: u64 = 1;
const RUN_ONCE_DONE: u64 = 2;
const RUN_ONCE_MASK: u64 = 3;
const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001u32 as i32;
const CV_LOCKMODE_SHARED: u32 = 1;

#[inline]
unsafe fn word<'a>(ptr: *mut u64) -> &'a AtomicU64 {
    // An RTL_SRWLOCK / RTL_CONDITION_VARIABLE / RTL_RUN_ONCE has
    // pointer-size alignment and storage, as guaranteed by its ABI.
    unsafe { AtomicU64::from_ptr(ptr) }
}

#[inline]
fn yield_execution() {
    unsafe { crate::NtYieldExecution(); }
}

// -----| RTL_RUN_ONCE |-----

type RunOnceCallback =
    unsafe extern "system" fn(*mut u64, usize, *mut usize) -> u32;

#[no_mangle]
pub unsafe extern "system" fn RtlRunOnceInitialize(once: *mut u64) {
    if !once.is_null() {
        unsafe { word(once).store(0, Ordering::Release) };
    }
}

/// Return an NTSTATUS, not BOOL. The callback returns a nonzero
/// ULONG/LOGICAL for success. Subsequent callers receive the same context.
#[no_mangle]
pub unsafe extern "system" fn RtlRunOnceExecuteOnce(
    once: *mut u64,
    callback: RunOnceCallback,
    parameter: usize,
    context: *mut usize,
) -> NtStatus {
    if once.is_null() {
        return status::INVALID_PARAMETER;
    }

    let state = unsafe { word(once) };
    loop {
        match state.load(Ordering::Acquire) {
            0 => {
                if state.compare_exchange(
                    0, RUN_ONCE_BUSY,
                    Ordering::AcqRel, Ordering::Acquire,
                ).is_err() {
                    continue;
                }

                // Do not hold an OS-wide lock while user code runs.
                let mut value = 0usize;
                let out = if context.is_null() {
                    core::ptr::null_mut()
                } else {
                    &mut value as *mut usize
                };

                let ok = unsafe { callback(once, parameter, out) } != 0;
                if !ok {
                    state.store(0, Ordering::Release); // allow retry
                    return STATUS_UNSUCCESSFUL;
                }
                if (value as u64 & RUN_ONCE_MASK) != 0 {
                    state.store(0, Ordering::Release);
                    return status::INVALID_PARAMETER;
                }

                state.store(value as u64 | RUN_ONCE_DONE, Ordering::Release);
                if !context.is_null() {
                    unsafe { *context = value };
                }
                return status::SUCCESS;
            }
            RUN_ONCE_BUSY => yield_execution(),
            done if (done & RUN_ONCE_MASK) == RUN_ONCE_DONE => {
                if !context.is_null() {
                    unsafe { *context = (done & !RUN_ONCE_MASK) as usize };
                }
                return status::SUCCESS;
            }
            _ => return status::INVALID_PARAMETER, // reserved / invalid state
        }
    }
}

// -----| Slim reader/writer locks |-----

#[no_mangle]
pub unsafe extern "system" fn RtlInitializeSRWLock(lock: *mut u64) {
    unsafe { word(lock).store(0, Ordering::Release) };
}

#[no_mangle]
pub unsafe extern "system" fn RtlTryAcquireSRWLockExclusive(lock: *mut u64) -> u8 {
    (unsafe { word(lock) }
        .compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()) as u8
}

#[no_mangle]
pub unsafe extern "system" fn RtlAcquireSRWLockExclusive(lock: *mut u64) {
    while unsafe { RtlTryAcquireSRWLockExclusive(lock) } == 0 {
        yield_execution();
    }
}

#[no_mangle]
pub unsafe extern "system" fn RtlReleaseSRWLockExclusive(lock: *mut u64) {
    unsafe { word(lock).store(0, Ordering::Release) };
}

#[no_mangle]
pub unsafe extern "system" fn RtlTryAcquireSRWLockShared(lock: *mut u64) -> u8 {
    let state = unsafe { word(lock) };
    let current = state.load(Ordering::Relaxed);
    ((current & WRITER) == 0
        && current != WRITER - 1
        && state.compare_exchange(
            current, current + 1, Ordering::Acquire, Ordering::Relaxed,
        ).is_ok()) as u8
}

#[no_mangle]
pub unsafe extern "system" fn RtlAcquireSRWLockShared(lock: *mut u64) {
    while unsafe { RtlTryAcquireSRWLockShared(lock) } == 0 {
        yield_execution();
    }
}

#[no_mangle]
pub unsafe extern "system" fn RtlReleaseSRWLockShared(lock: *mut u64) {
    unsafe { word(lock).fetch_sub(1, Ordering::Release) };
}

// KUSER_SHARED_DATA has the same KSYSTEM_TIME layout as kernel32's clock:
// LowPart, High1Time, High2Time. TICK_COUNT is milliseconds; SYSTEM_TIME
// is a 100-ns FILETIME. Read twice if the high halves disagree.
fn kusd_time(offset: usize) -> u64 {
    let p = (kusd::ADDRESS + offset) as *const u32;
    loop {
        let high1 = unsafe { core::ptr::read_volatile(p.add(1)) };
        let low = unsafe { core::ptr::read_volatile(p) };
        let high2 = unsafe { core::ptr::read_volatile(p.add(2)) };
        if high1 == high2 {
            return ((high1 as u64) << 32) | low as u64;
        }
    }
}

fn tick_ms() -> u64 {
    kusd_time(kusd::TICK_COUNT)
}

fn system_filetime() -> u64 {
    kusd_time(kusd::SYSTEM_TIME)
}

// -----| Condition variables |-----
//
// VEILOS currently uses an eight-byte generation counter for condition
// variables. RtlWaitOnAddress blocks until a wake or timeout; the lock is
// reacquired on every return path, including STATUS_TIMEOUT.

#[no_mangle]
pub unsafe extern "system" fn RtlInitializeConditionVariable(cv: *mut u64) {
    unsafe { word(cv).store(0, Ordering::Release) };
}

#[no_mangle]
pub unsafe extern "system" fn RtlSleepConditionVariableSRW(
    cv: *mut u64,
    lock: *mut u64,
    timeout: *const i64,
    flags: u32,
) -> NtStatus {
    if cv.is_null() || lock.is_null() || (flags & !CV_LOCKMODE_SHARED) != 0 {
        return status::INVALID_PARAMETER;
    }

    let shared = (flags & CV_LOCKMODE_SHARED) != 0;
    let prior = unsafe { word(cv).load(Ordering::Acquire) };
    unsafe {
        if shared {
            RtlReleaseSRWLockShared(lock);
        } else {
            RtlReleaseSRWLockExclusive(lock);
        }
    }

    // Kernel32 currently implements condition variables as generation
    // counters too, but its WakeAllConditionVariable doesn't issue a
    // VeilWakeAddress syscall. Use at most 1-ms waits and re-check the
    // counter so calls through the two DLLs still interoperate.
    let deadline = if timeout.is_null() {
        None
    } else {
        let raw = unsafe { core::ptr::read_unaligned(timeout) };
        if raw <= 0 {
            // Relative 100-ns interval; round up to millisecond ticks.
            let duration = raw.unsigned_abs().saturating_add(9_999) / 10_000;
            Some((false, tick_ms().saturating_add(duration)))
        } else {
            // Positive LARGE_INTEGER is absolute NT FILETIME, in 100 ns.
            Some((true, raw as u64))
        }
    };

    let result = loop {
        if unsafe { word(cv).load(Ordering::Acquire) } != prior {
            break status::SUCCESS;
        }
        if let Some((absolute, end)) = deadline {
            let now = if absolute { system_filetime() } else { tick_ms() };
            if now >= end {
                break status::TIMEOUT;
            }
        }
        const ONE_MS: i64 = -10_000;
        let s = unsafe {
            crate::rtl::RtlWaitOnAddress(
                cv.cast::<u8>(),
                (&prior as *const u64).cast::<u8>(),
                core::mem::size_of::<u64>(),
                &ONE_MS,
            )
        };
        if s != status::SUCCESS && s != status::TIMEOUT {
            break s;
        }
    };

    // Even on timeout or error, POSIX/Windows-style condition variables
    // return with the original lock acquired.
    unsafe {
        if shared {
            RtlAcquireSRWLockShared(lock);
        } else {
            RtlAcquireSRWLockExclusive(lock);
        }
    }
    result
}

#[no_mangle]
pub unsafe extern "system" fn RtlWakeAllConditionVariable(cv: *mut u64) {
    if cv.is_null() {
        return;
    }
    unsafe {
        word(cv).fetch_add(1, Ordering::Release);
        crate::rtl::RtlWakeAddressAll(cv.cast::<u8>());
    }
}
