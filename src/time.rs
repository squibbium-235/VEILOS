// =============================================================================
// VEILOS: kernel timebase
// =============================================================================
//
// The TSC is calibrated once at boot against PIT channel 2 and is then the
// clock for busy-wait delays and driver timeouts (`delay_us`, `Deadline`,
// `spin_until`). Before this, drivers counted loop iterations, so a "500 ms"
// timeout lasted anywhere from microseconds to seconds depending on the CPU
// and accelerator.
//
// The PIT channel-0 interrupt (1 kHz) still drives the scheduler and
// SleepFuture wakeups, but the time it publishes (`interrupts::TICKS`) is
// read from the TSC, so lost interrupts don't slow the clock. Channel 2 is
// used here so channel 0 is never disturbed.
//
// `calibrate` is shared with `smp`, which measures the LAPIC timer the same
// way.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use x86_64::instructions::port::Port;

/// PIT input clock.
pub const PIT_HZ: u64 = 1_193_182;

/// Calibration window: 10 ms of PIT channel 2 (fits the 16-bit counter).
const CALIBRATION_PIT_COUNTS: u16 = 11_932;
/// Rounds per calibration; the shortest is kept, since an SMI or a host
/// preemption can only make a round look longer.
const CALIBRATION_ROUNDS: usize = 3;

/// Used if calibration fails. Deliberately high: on a slower CPU delays and
/// timeouts run long, never short.
const FALLBACK_TSC_HZ: u64 = 4_000_000_000;

static TSC_HZ: AtomicU64 = AtomicU64::new(FALLBACK_TSC_HZ);
static TSC_BOOT: AtomicU64 = AtomicU64::new(0);
static TSC_CALIBRATED: AtomicBool = AtomicBool::new(false);

#[inline(always)]
pub fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Run PIT channel 2 one-shot for `counts` input clocks, sampling `sample`
/// right after it starts and right after it fires. Returns `None` if OUT2
/// never rises (no working channel 2).
fn pit_ch2_measure(counts: u16, sample: &mut impl FnMut() -> u64) -> Option<(u64, u64)> {
    let mut gate: Port<u8> = Port::new(0x61); // ch2 gate + speaker control
    let mut cmd:  Port<u8> = Port::new(0x43);
    let mut ch2:  Port<u8> = Port::new(0x42);
    unsafe {
        let saved = gate.read();
        gate.write(saved & !0x03);          // gate low, speaker off
        cmd.write(0b1011_0000);             // ch2, lobyte/hibyte, mode 0, binary
        ch2.write(counts as u8);
        ch2.write((counts >> 8) as u8);
        gate.write((saved & !0x02) | 0x01); // gate high: start counting
        let start = sample();
        // OUT2 (bit 5 of 0x61) rises at terminal count. Bounded so a machine
        // without channel 2 cannot hang boot.
        let mut polls = 0u32;
        while gate.read() & 0x20 == 0 {
            polls += 1;
            if polls >= 5_000_000 {
                gate.write(saved);
                return None;
            }
        }
        let end = sample();
        gate.write(saved);
        Some((start, end))
    }
}

/// Measure how fast `sample` advances, in units per second, against PIT
/// channel 2. `sample` must be monotonic over the 10 ms window. Runs with
/// interrupts off. Returns `None` if channel 2 doesn't work.
pub(crate) fn calibrate(mut sample: impl FnMut() -> u64) -> Option<u64> {
    let best = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut best = u64::MAX;
        for _ in 0..CALIBRATION_ROUNDS {
            if let Some((a, b)) = pit_ch2_measure(CALIBRATION_PIT_COUNTS, &mut sample) {
                best = best.min(b.wrapping_sub(a));
            }
        }
        best
    });
    if best == u64::MAX || best == 0 {
        return None;
    }
    Some((best as u128 * PIT_HZ as u128 / CALIBRATION_PIT_COUNTS as u128) as u64)
}

fn tsc_is_invariant() -> bool {
    use core::arch::x86_64::__cpuid;
    unsafe { __cpuid(0x8000_0000) }.eax >= 0x8000_0007
        && unsafe { __cpuid(0x8000_0007) }.edx & (1 << 8) != 0
}

/// Calibrate the TSC. Call once on the BSP, early in boot (needs only port I/O).
pub fn init() {
    TSC_BOOT.store(rdtsc(), Ordering::Relaxed);
    let invariant = tsc_is_invariant();
    match calibrate(rdtsc) {
        Some(hz) => {
            TSC_HZ.store(hz, Ordering::Relaxed);
            TSC_CALIBRATED.store(true, Ordering::Release);
            crate::serial_println!(
                "[TIME] TSC {}.{:03} MHz (invariant: {})",
                hz / 1_000_000, (hz / 1_000) % 1_000, invariant
            );
        }
        None => {
            crate::serial_println!(
                "[TIME] WARN: PIT channel 2 did not respond; assuming a {} MHz TSC (delays will run long)",
                FALLBACK_TSC_HZ / 1_000_000
            );
        }
    }
}

pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

pub fn is_calibrated() -> bool {
    TSC_CALIBRATED.load(Ordering::Acquire)
}

#[inline]
fn us_to_tsc(us: u64) -> u64 {
    (us as u128 * tsc_hz() as u128 / 1_000_000) as u64
}

/// Microseconds since `init`.
pub fn now_us() -> u64 {
    let elapsed = rdtsc().wrapping_sub(TSC_BOOT.load(Ordering::Relaxed));
    (elapsed as u128 * 1_000_000 / tsc_hz() as u128) as u64
}

/// Milliseconds since `init`.
pub fn now_ms() -> u64 {
    now_us() / 1_000
}

/// Nanoseconds since `init`.
pub fn now_ns() -> u64 {
    let elapsed = rdtsc().wrapping_sub(TSC_BOOT.load(Ordering::Relaxed));
    (elapsed as u128 * 1_000_000_000 / tsc_hz() as u128) as u64
}

/// Busy-wait for `us` microseconds. Works with interrupts on or off.
pub fn delay_us(us: u64) {
    Deadline::after_us(us).wait();
}

/// Busy-wait for `ms` milliseconds. For long waits with interrupts on, prefer
/// `interrupts::SleepFuture` so the executor keeps running.
pub fn delay_ms(ms: u64) {
    delay_us(ms.saturating_mul(1_000));
}

/// A point in time measured on the TSC, for driver timeouts.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    end_tsc: u64,
}

impl Deadline {
    pub fn after_us(us: u64) -> Self {
        Self { end_tsc: rdtsc().saturating_add(us_to_tsc(us)) }
    }

    pub fn after_ms(ms: u64) -> Self {
        Self::after_us(ms.saturating_mul(1_000))
    }

    pub fn expired(&self) -> bool {
        rdtsc() >= self.end_tsc
    }

    pub fn wait(&self) {
        while !self.expired() {
            core::hint::spin_loop();
        }
    }
}

/// Poll `done` until it returns true or `timeout_us` passes. Returns whether
/// `done` succeeded (it is checked once more after the deadline, so a slow
/// final poll can't be reported as a timeout).
pub fn spin_until(timeout_us: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Deadline::after_us(timeout_us);
    loop {
        if done() {
            return true;
        }
        if deadline.expired() {
            return done();
        }
        core::hint::spin_loop();
    }
}
