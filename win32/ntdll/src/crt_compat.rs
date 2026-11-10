//! Small CRT/RTL functions that some system components import directly from
//! ntdll rather than ucrtbase. These do not require kernel-mode support.

/// errno_t strcpy_s: EINVAL 22, ERANGE 34. Clear destination on error.
#[no_mangle]
pub unsafe extern "C" fn strcpy_s(dst: *mut u8, capacity: usize, src: *const u8) -> i32 {
    if dst.is_null() || capacity == 0 { return 22; }
    if src.is_null() {
        unsafe { *dst = 0; }
        return 22;
    }
    let mut i = 0usize;
    while i < capacity {
        let ch = unsafe { src.add(i).read_volatile() };
        unsafe { dst.add(i).write_volatile(ch); }
        if ch == 0 { return 0; }
        i += 1;
    }
    unsafe { *dst = 0; }
    34
}

#[inline]
fn fold(ch: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&ch) { ch + 32 } else { ch }
}

/// Simple Unicode case folding is ASCII-only until VEILOS adds NLS tables.
#[no_mangle]
pub unsafe extern "C" fn _wcsicmp(a: *const u16, b: *const u16) -> i32 {
    if a.is_null() || b.is_null() { return if a == b { 0 } else { -1 }; }
    let mut i = 0usize;
    loop {
        let left = fold(unsafe { *a.add(i) });
        let right = fold(unsafe { *b.add(i) });
        if left != right { return left as i32 - right as i32; }
        if left == 0 { return 0; }
        i += 1;
    }
}

#[no_mangle]
pub extern "C" fn iswspace(ch: u16) -> i32 {
    (matches!(ch, 0x09..=0x0d | 0x20 | 0x85 | 0xa0 | 0x1680 |
        0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)) as i32
}

/// VEILOS is a single interactive desktop session, not an RDS server SKU.
#[no_mangle]
pub extern "system" fn RtlIsMultiSessionSku() -> u8 { 0 }
