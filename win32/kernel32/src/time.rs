//! Tick counts, the performance counter, system time and Sleep. The clocks
//! come from KUSER_SHARED_DATA, which the kernel keeps current; the
//! performance counter is the TSC.

use nt_abi::kusd;

use crate::Bool;

fn kusd_u64(offset: usize) -> u64 {
    unsafe { core::ptr::read_volatile((kusd::ADDRESS + offset) as *const u64) }
}

/// A KSYSTEM_TIME field: read until High1Time and High2Time agree.
fn ksystem_time(offset: usize) -> u64 {
    loop {
        let p = (kusd::ADDRESS + offset) as *const u32;
        let high1 = unsafe { core::ptr::read_volatile(p.add(1)) };
        let low = unsafe { core::ptr::read_volatile(p) };
        let high2 = unsafe { core::ptr::read_volatile(p.add(2)) };
        if high1 == high2 {
            return ((high1 as u64) << 32) | low as u64;
        }
    }
}

#[no_mangle]
pub extern "system" fn GetTickCount() -> u32 {
    ksystem_time(kusd::TICK_COUNT) as u32
}

#[no_mangle]
pub extern "system" fn GetTickCount64() -> u64 {
    ksystem_time(kusd::TICK_COUNT)
}

#[no_mangle]
pub unsafe extern "system" fn QueryPerformanceCounter(count: *mut i64) -> Bool {
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    unsafe { *count = tsc as i64 };
    1
}

#[no_mangle]
pub unsafe extern "system" fn QueryPerformanceFrequency(frequency: *mut i64) -> Bool {
    unsafe { *frequency = kusd_u64(kusd::QPC_FREQUENCY) as i64 };
    1
}

#[no_mangle]
pub extern "system" fn VeilQueryPerfCounter() -> i64 {
    let mut value: i64 = 0;

    if unsafe { QueryPerformanceCounter(&mut value) } != 0 {
        value
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn VeilQueryPerfFrequency() -> i64 {
    let mut value: i64 = 0;

    if unsafe { QueryPerformanceFrequency(&mut value) } != 0 {
        value
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "system" fn GetSystemTimeAsFileTime(ft: *mut u64) {
    unsafe { core::ptr::write_unaligned(ft, ksystem_time(kusd::SYSTEM_TIME)) };
}

#[no_mangle]
pub unsafe extern "system" fn GetSystemTimePreciseAsFileTime(ft: *mut u64) {
    unsafe { GetSystemTimeAsFileTime(ft) };
}

/// SYSTEMTIME: year, month, day of week, day, hour, minute, second, ms.
#[repr(C)]
pub struct SystemTime {
    pub(crate) year: u16,
    pub(crate) month: u16,
    pub(crate) day_of_week: u16,
    pub(crate) day: u16,
    pub(crate) hour: u16,
    pub(crate) minute: u16,
    pub(crate) second: u16,
    pub(crate) milliseconds: u16,
}

/// Days since 1601-01-01 → (year, month, day): civil_from_days (Howard
/// Hinnant), with the epoch moved from 1970.
fn civil(days_1601: i64) -> (i64, u16, u16) {
    let z = days_1601 - 134_774 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u16;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u16;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

fn days_1601(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468 + 134_774
}

#[no_mangle]
pub unsafe extern "system" fn FileTimeToSystemTime(ft: *const u64, st: *mut SystemTime) -> Bool {
    let t = unsafe { core::ptr::read_unaligned(ft) };
    if t > 0x7FFF_FFFF_FFFF_FFFF {
        return crate::fail(nt_abi::status::INVALID_PARAMETER);
    }
    let ms_total = t / 10_000;
    let days = (ms_total / 86_400_000) as i64;
    let ms = ms_total % 86_400_000;
    let (y, m, d) = civil(days);
    unsafe {
        *st = SystemTime {
            year: y as u16,
            month: m,
            day_of_week: ((days + 1) % 7) as u16, // 1601-01-01 was a Monday
            day: d,
            hour: (ms / 3_600_000) as u16,
            minute: (ms / 60_000 % 60) as u16,
            second: (ms / 1000 % 60) as u16,
            milliseconds: (ms % 1000) as u16,
        }
    };
    1
}

#[no_mangle]
pub unsafe extern "system" fn SystemTimeToFileTime(st: *const SystemTime, ft: *mut u64) -> Bool {
    let s = unsafe { &*st };
    if !(1..=12).contains(&s.month) || !(1..=31).contains(&s.day) || s.hour > 23 || s.minute > 59 || s.second > 59 || s.milliseconds > 999 {
        return crate::fail(nt_abi::status::INVALID_PARAMETER);
    }
    let days = days_1601(s.year as i64, s.month as i64, s.day as i64);
    let ms = days as u64 * 86_400_000 + s.hour as u64 * 3_600_000 + s.minute as u64 * 60_000 + s.second as u64 * 1000 + s.milliseconds as u64;
    unsafe { core::ptr::write_unaligned(ft, ms * 10_000) };
    1
}

#[no_mangle]
pub unsafe extern "system" fn GetSystemTime(st: *mut SystemTime) {
    let ft = ksystem_time(kusd::SYSTEM_TIME);
    unsafe { FileTimeToSystemTime(&ft, st) };
}

/// The time zone is UTC: local time is system time.
#[no_mangle]
pub unsafe extern "system" fn GetLocalTime(st: *mut SystemTime) {
    unsafe { GetSystemTime(st) };
}

#[no_mangle]
pub unsafe extern "system" fn FileTimeToLocalFileTime(ft: *const u64, local: *mut u64) -> Bool {
    unsafe { core::ptr::write_unaligned(local, core::ptr::read_unaligned(ft)) };
    1
}

#[no_mangle]
pub unsafe extern "system" fn LocalFileTimeToFileTime(local: *const u64, ft: *mut u64) -> Bool {
    unsafe { core::ptr::write_unaligned(ft, core::ptr::read_unaligned(local)) };
    1
}

/// TIME_ZONE_INFORMATION (172 bytes), all zero: UTC, no daylight time.
#[no_mangle]
pub unsafe extern "system" fn GetTimeZoneInformation(info: *mut u8) -> u32 {
    unsafe { core::ptr::write_bytes(info, 0, 172) };
    0 // TIME_ZONE_ID_UNKNOWN
}

#[no_mangle]
pub extern "system" fn Sleep(ms: u32) {
    SleepEx(ms, 0);
}

#[no_mangle]
pub extern "system" fn SleepEx(ms: u32, alertable: Bool) -> u32 {
    if alertable != 0 {
        // WAIT_IO_COMPLETION if an APC ran, else 0 once the time is up.
        let r = crate::apc::alertable(ms, |t| {
            SleepEx(t, 0);
            258
        });
        return if r == crate::apc::WAIT_IO_COMPLETION { r } else { 0 };
    }
    // INFINITE: the longest the interval can say.
    let interval: i64 = if ms == u32::MAX { i64::MIN + 1 } else { -(ms as i64) * 10_000 };
    unsafe { crate::NtDelayExecution(0, &interval) };
    0
}
