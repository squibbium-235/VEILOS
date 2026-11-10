//! MSVC _timespec64 wall-clock helpers (Windows epoch conversion).
use core::cmp;
use crate::abi::*;

#[no_mangle]
pub extern "system" fn _Xtime_get_ticks() -> i64 {
    let mut ft = Filetime::default();
    unsafe { GetSystemTimeAsFileTime(&mut ft); }
    let windows_ticks = ((ft.high as u64) << 32) | ft.low as u64;
    (windows_ticks as i64).saturating_sub(116_444_736_000_000_000)
}

pub fn until_ms(target: *const Timespec64) -> u32 {
    if target.is_null() { return INFINITE; }
    let t = unsafe { *target };
    let now = _Xtime_get_ticks() as i128;
    let goal = (t.sec as i128) * 10_000_000 + (t.nsec as i128) / 100;
    if goal <= now { return 0; }
    let difference = goal - now;
    let milliseconds = (difference + 9_999) / 10_000;
    cmp::min(milliseconds, (u32::MAX - 1) as i128) as u32
}

#[no_mangle]
pub extern "system" fn _Xtime_diff_to_millis(t: *const Timespec64) -> i32 {
    cmp::min(until_ms(t), i32::MAX as u32) as i32
}

#[no_mangle]
pub extern "system" fn _Xtime_diff_to_millis2(
    target: *const Timespec64, now: *const Timespec64,
) -> i32 {
    if target.is_null() || now.is_null() { return 0; }
    let target = unsafe { *target };
    let now = unsafe { *now };
    let delta_ns = ((target.sec as i128) - (now.sec as i128)) * 1_000_000_000
        + ((target.nsec as i128) - (now.nsec as i128));
    if delta_ns <= 0 { return 0; }
    cmp::min((delta_ns + 999_999) / 1_000_000, i32::MAX as i128) as i32
}
