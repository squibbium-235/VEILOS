//! Win32 ACL/SID wrappers. ACL storage is implemented in NTDLL; VEILOS
//! currently has no discretionary access enforcement at the VFS boundary.
//! Callers can construct and examine ACLs without falsely claiming policy
//! enforcement.
use crate::{Bool, Handle};
use core::ptr::{read_unaligned, write_unaligned};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn RtlAddAccessAllowedAce(acl: *mut u8, revision: u32, mask: u32, sid: *const u8) -> i32;
    fn RtlAddAccessAllowedAceEx(acl: *mut u8, revision: u32, flags: u32, mask: u32, sid: *const u8) -> i32;
    fn RtlAddAccessDeniedAceEx(acl: *mut u8, revision: u32, flags: u32, mask: u32, sid: *const u8) -> i32;
}

#[no_mangle]
pub unsafe extern "system" fn AddAccessAllowedAce(acl: *mut u8, revision: u32, mask: u32, sid: *const u8) -> Bool {
    if acl.is_null() || sid.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    crate::check(unsafe { RtlAddAccessAllowedAce(acl, revision, mask, sid) })
}

#[no_mangle]
pub unsafe extern "system" fn AddAccessAllowedAceEx(acl: *mut u8, revision: u32, flags: u32, mask: u32, sid: *const u8) -> Bool {
    if acl.is_null() || sid.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    crate::check(unsafe { RtlAddAccessAllowedAceEx(acl, revision, flags, mask, sid) })
}

#[no_mangle]
pub unsafe extern "system" fn AddAccessDeniedAceEx(acl: *mut u8, revision: u32, flags: u32, mask: u32, sid: *const u8) -> Bool {
    if acl.is_null() || sid.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    crate::check(unsafe { RtlAddAccessDeniedAceEx(acl, revision, flags, mask, sid) })
}

// WELL_KNOWN_SID_TYPE. Domain-relative types need an actual domain SID and
// are deliberately rejected until VEILOS implements domain identities.
fn known_sid(kind: u32) -> Option<(&'static [u8; 6], &'static [u32])> {
    const NULL: [u8; 6] = [0, 0, 0, 0, 0, 0];
    const NT: [u8; 6] = [0, 0, 0, 0, 0, 5];
    const WORLD: [u8; 6] = [0, 0, 0, 0, 0, 1];
    const LOCAL: [u8; 6] = [0, 0, 0, 0, 0, 2];
    const CREATOR: [u8; 6] = [0, 0, 0, 0, 0, 3];
    match kind {
        0 => Some((&NULL, &[0])),                 // WinNullSid
        1 => Some((&WORLD, &[0])),                  // WinWorldSid
        2 => Some((&LOCAL, &[0])),                  // WinLocalSid
        3 => Some((&CREATOR, &[0])),                // WinCreatorOwnerSid
        4 => Some((&CREATOR, &[1])),                // WinCreatorGroupSid
        11 => Some((&NT, &[4])),                   // WinInteractiveSid
        12 => Some((&NT, &[6])),                   // WinServiceSid
        13 => Some((&NT, &[7])),                   // WinAnonymousSid
        17 => Some((&NT, &[11])),                  // WinAuthenticatedUserSid
        18 => Some((&NT, &[12])),                  // WinRestrictedCodeSid
        22 => Some((&NT, &[18])),                  // WinLocalSystemSid
        23 => Some((&NT, &[19])),                  // WinLocalServiceSid
        24 => Some((&NT, &[20])),                  // WinNetworkServiceSid
        25 => Some((&NT, &[32])),                  // WinBuiltinDomainSid
        26 => Some((&NT, &[32, 544])),             // WinBuiltinAdministratorsSid
        27 => Some((&NT, &[32, 545])),             // WinBuiltinUsersSid
        28 => Some((&NT, &[32, 546])),             // WinBuiltinGuestsSid
        _ => None,
    }
}

#[no_mangle]
pub unsafe extern "system" fn CreateWellKnownSid(kind: u32, domain: *const u8, sid: *mut u8, size: *mut u32) -> Bool {
    if size.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    // Domain-relative SID construction isn't supported by this table.
    let _ = domain;
    let Some((authority, sub)) = known_sid(kind) else {
        crate::SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let required = (8 + 4 * sub.len()) as u32;
    let cap = unsafe { *size };
    unsafe { *size = required; }
    if sid.is_null() || cap < required {
        crate::SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    unsafe {
        *sid = 1;
        *sid.add(1) = sub.len() as u8;
        core::ptr::copy_nonoverlapping(authority.as_ptr(), sid.add(2), 6);
        for (i, &v) in sub.iter().enumerate() {
            write_unaligned(sid.add(8 + 4 * i) as *mut u32, v);
        }
    }
    1
}

/// Structural ACL validation: header, bounds, and ACE sizes.
#[no_mangle]
pub unsafe extern "system" fn IsValidAcl(acl: *const u8) -> Bool {
    if acl.is_null() { return 0; }
    unsafe {
        let revision = *acl;
        let bytes = read_unaligned(acl.add(2) as *const u16) as usize;
        let count = read_unaligned(acl.add(4) as *const u16) as usize;
        if !(2..=4).contains(&revision) || bytes < 8 { return 0; }
        let mut pos = 8usize;
        for _ in 0..count {
            if pos + 4 > bytes { return 0; }
            let len = read_unaligned(acl.add(pos + 2) as *const u16) as usize;
            if len < 4 || len % 4 != 0 || len > bytes - pos { return 0; }
            pos += len;
        }
        1
    }
}

/// TRUSTEE_W has a 32-byte, x64 ABI layout.
#[repr(C)]
struct TrusteeW {
    multiple_trustee: usize,
    multiple_trustee_operation: u32,
    trustee_form: u32,
    trustee_type: u32,
    name: *mut u16,
}

#[no_mangle]
pub unsafe extern "system" fn BuildTrusteeWithSidW(trustee: *mut u8, sid: *const u8) {
    if trustee.is_null() { return; }
    unsafe {
        let t = trustee as *mut TrusteeW;
        core::ptr::write_bytes(t, 0, 1);
        (*t).trustee_form = 0; // TRUSTEE_IS_SID
        (*t).trustee_type = 0; // TRUSTEE_IS_UNKNOWN
        (*t).name = sid as *mut u16;
    }
}

/// No registry key cache currently exists, so disabling it is a no-op.
#[no_mangle]
pub extern "system" fn RegDisablePredefinedCache() -> u32 { 0 }

/// No active access-token enforcement. Report unsupported, not access granted.
#[no_mangle]
pub unsafe extern "system" fn AccessCheck(
    _sd: *const u8, _token: Handle, _desired: u32, _mapping: *const u8,
    _privilege_set: *mut u8, _privilege_size: *mut u32, _granted: *mut u32, _status: *mut Bool,
) -> Bool {
    crate::SetLastError(50); // ERROR_NOT_SUPPORTED
    0
}

/// A per-boot locally unique ID: high part is the process ID and the low
/// part is a per-process monotonic counter (no security properties).
static LUID_SEQUENCE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
#[no_mangle]
pub unsafe extern "system" fn AllocateLocallyUniqueId(out: *mut u64) -> Bool {
    if out.is_null() { crate::SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    let sequence = LUID_SEQUENCE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let id = (u64::from(crate::GetCurrentProcessId()) << 32) | u64::from(sequence);
    unsafe { core::ptr::write_unaligned(out, id); }
    1
}
