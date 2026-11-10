//! Build an ACL from EXPLICIT_ACCESS entries, backed by LocalAlloc.
//!
//! This is structural ACL manipulation only. VEILOS does not yet enforce
//! Windows ACLs on VFS operations. Object-specific ACEs and complex trustee
//! mappings are rejected instead of pretending to enforce them.
use core::ptr::{copy, copy_nonoverlapping, read_unaligned, write_bytes, write_unaligned};

const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_NOT_SUPPORTED: u32 = 50;
const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_INVALID_ACL: u32 = 1336;
const ERROR_ALLOTTED_SPACE_EXCEEDED: u32 = 1344;

// TRUSTEE is 32 bytes on Win64. EXPLICIT_ACCESS starts its TRUSTEE at +16.
#[repr(C)]
#[derive(Clone, Copy)]
struct Trustee {
    multiple: *const u8,
    operation: u32,
    form: u32,
    kind: u32,
    name: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExplicitAccess {
    permissions: u32,
    mode: u32,
    inheritance: u32,
    trustee: Trustee,
}

// TRUSTEE_IS_OBJECTS_AND_SID, with *SID at offset 40 on Win64.
#[repr(C)]
struct ObjectsAndSid {
    objects_present: u32,
    object_type: [u8; 16],
    inherited_object_type: [u8; 16],
    sid: *const u8,
}

// Compare a known simple trustee name without allocating.
unsafe fn name_is(ptr: *const u8, ansi: bool, expected: &[u8]) -> bool {
    if ptr.is_null() { return false; }
    for (i, &char_) in expected.iter().enumerate() {
        let got = if ansi {
            (unsafe { *ptr.add(i) }) as u16
        } else {
            unsafe { read_unaligned(ptr.add(i * 2) as *const u16) }
        };
        if got > 127 || (got as u8).to_ascii_lowercase() != char_.to_ascii_lowercase() { return false; }
    }
    let end = if ansi {
        (unsafe { *ptr.add(expected.len()) }) as u16
    } else {
        unsafe { read_unaligned(ptr.add(expected.len() * 2) as *const u16) }
    };
    end == 0
}

// Fill a bounded local SID copy, which also normalizes the name forms.
unsafe fn sid_of(entry: &ExplicitAccess, ansi: bool, sid: &mut [u8; 68]) -> Result<usize, u32> {
    if !entry.trustee.multiple.is_null() || entry.trustee.operation != 0 {
        return Err(ERROR_NOT_SUPPORTED);
    }
    let p = match entry.trustee.form {
        0 => entry.trustee.name, // TRUSTEE_IS_SID
        3 => {
            if entry.trustee.name.is_null() { return Err(ERROR_INVALID_PARAMETER); }
            let object = entry.trustee.name as *const ObjectsAndSid;
            if unsafe { (*object).objects_present } != 0 { return Err(ERROR_NOT_SUPPORTED); }
            unsafe { (*object).sid }
        }
        1 => { // TRUSTEE_IS_NAME: resolve only known local identities.
            let name = entry.trustee.name;
            let bytes: &[u8] = if unsafe { name_is(name, ansi, b"Everyone") } {
                &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
            } else if unsafe { name_is(name, ansi, b"SYSTEM") } || unsafe { name_is(name, ansi, b"NT AUTHORITY\\SYSTEM") } {
                &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
            } else if unsafe { name_is(name, ansi, b"Administrators") } || unsafe { name_is(name, ansi, b"BUILTIN\\Administrators") } {
                &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
            } else if unsafe { name_is(name, ansi, b"Users") } || unsafe { name_is(name, ansi, b"BUILTIN\\Users") } {
                &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0]
            } else if unsafe { name_is(name, ansi, b"Authenticated Users") } {
                &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0]
            } else {
                return Err(ERROR_NONE_MAPPED);
            };
            sid[..bytes.len()].copy_from_slice(bytes);
            return Ok(bytes.len());
        }
        _ => return Err(ERROR_NOT_SUPPORTED),
    };
    if p.is_null() { return Err(ERROR_INVALID_PARAMETER); }
    let rev = unsafe { *p };
    let count = unsafe { *p.add(1) };
    if rev != 1 || count > 15 { return Err(ERROR_INVALID_PARAMETER); }
    let len = 8 + 4 * count as usize;
    unsafe { copy_nonoverlapping(p, sid.as_mut_ptr(), len) };
    Ok(len)
}

// ACE types 0=allowed, 1=denied, 2=system audit. Other ACE kinds are
// preserved verbatim, so an inherited/object ACE isn't silently discarded.
unsafe fn ace_sid_matches(ace: *const u8, ace_len: usize, target: &[u8]) -> bool {
    if ace_len < 16 { return false; }
    let kind = unsafe { *ace };
    if kind > 2 { return false; }
    let sid = unsafe { ace.add(8) };
    let n = unsafe { *sid.add(1) } as usize;
    let len = 8 + n * 4;
    len == target.len() && 8 + len <= ace_len && unsafe { core::slice::from_raw_parts(sid, len) } == target
}

/// Returns the end of the last ACE and the number of ACEs. Checks against
/// AclSize instead of trusting AceCount to be internally consistent.
unsafe fn acl_used(acl: *const u8) -> Option<(usize, u16)> {
    if acl.is_null() || !(2..=4).contains(&unsafe { *acl }) { return None; }
    let capacity = unsafe { read_unaligned(acl.add(2) as *const u16) } as usize;
    let count = unsafe { read_unaligned(acl.add(4) as *const u16) };
    if capacity < 8 { return None; }
    let mut used = 8usize;
    for _ in 0..count {
        if capacity - used < 4 { return None; }
        let len = unsafe { read_unaligned(acl.add(used + 2) as *const u16) } as usize;
        if len < 4 || len & 3 != 0 || len > capacity - used { return None; }
        used += len;
    }
    Some((used, count))
}

unsafe fn make_entries(count: u32, entries: *const ExplicitAccess, old: *const u8, out: *mut *mut u8, ansi: bool) -> u32 {
    if out.is_null() { return ERROR_INVALID_PARAMETER; }
    unsafe { *out = core::ptr::null_mut() };
    if count > 4096 || (count > 0 && entries.is_null()) { return ERROR_INVALID_PARAMETER; }
    if count == 0 && old.is_null() { return 0; }

    let (old_used, old_count) = if old.is_null() {
        (8usize, 0u16)
    } else if let Some(v) = unsafe { acl_used(old) } {
        v
    } else { return ERROR_INVALID_ACL; };

    // Preflight both arithmetic and trustees before allocating any memory.
    let mut capacity = old_used;
    for i in 0..count as usize {
        let e = unsafe { &*entries.add(i) };
        if !(1..=7).contains(&e.mode) || e.inheritance & !0xff != 0 { return ERROR_INVALID_PARAMETER; }
        let mut sid = [0u8; 68];
        let len = match unsafe { sid_of(e, ansi, &mut sid) } { Ok(v) => v, Err(v) => return v };
        if e.mode != 4 { // REVOKE_ACCESS only removes ACEs.
            let Some(next) = capacity.checked_add(8 + len) else { return ERROR_ALLOTTED_SPACE_EXCEEDED; };
            capacity = next;
        }
    }
    if capacity > u16::MAX as usize { return ERROR_ALLOTTED_SPACE_EXCEEDED; }
    let acl = crate::mem::LocalAlloc(0x40, capacity); // LPTR: caller releases via LocalFree.
    if acl.is_null() { return ERROR_NOT_ENOUGH_MEMORY; }
    unsafe {
        write_bytes(acl, 0, capacity);
        *acl = if old.is_null() { 2 } else { *old };
        write_unaligned(acl.add(2) as *mut u16, capacity as u16);
        write_unaligned(acl.add(4) as *mut u16, old_count);
        if !old.is_null() && old_used > 8 { copy_nonoverlapping(old.add(8), acl.add(8), old_used - 8); }
    }
    let mut used = old_used;
    let mut ace_count = old_count;

    for i in 0..count as usize {
        let e = unsafe { &*entries.add(i) };
        let mut sid = [0u8; 68];
        let len = match unsafe { sid_of(e, ansi, &mut sid) } {
            Ok(v) => v,
            Err(error) => { crate::mem::LocalFree(acl); return error; }
        };
        let mut mask = e.permissions;
        let mode = e.mode;
        let kind: u8 = match mode {
            1 | 2 => 0, // GRANT_ACCESS, SET_ACCESS
            3 => 1,     // DENY_ACCESS
            5..=7 => 2, // audit success/failure/both
            4 => 0,     // REVOKE_ACCESS; no new ACE
            _ => unreachable!(),
        };
        let audit_flags: u8 = match mode { 5 => 0x40, 6 => 0x80, 7 => 0xC0, _ => 0 };

        let mut pos = 8usize;
        while pos < used {
            let ace = unsafe { acl.add(pos) };
            let size = unsafe { read_unaligned(ace.add(2) as *const u16) } as usize;
            let old_kind = unsafe { *ace };
            let matching = unsafe { ace_sid_matches(ace, size, &sid[..len]) };
            let remove = matching && match mode {
                1 => old_kind == 0,             // GRANT: combine existing allowed mask
                2 => old_kind <= 1,             // SET: replace existing access entries
                3 => old_kind == 1,             // DENY: combine existing denied mask
                4 => old_kind == 0 || old_kind == 2, // REVOKE: remove allow/audit
                _ => old_kind == 2,             // merge audit entries
            };
            if remove {
                if mode == 1 || mode == 3 || mode >= 5 {
                    mask |= unsafe { read_unaligned(ace.add(4) as *const u32) };
                }
                unsafe { copy(ace.add(size), ace, used - pos - size) };
                used -= size;
                ace_count -= 1;
            } else {
                pos += size;
            }
        }
        if mode == 4 { continue; }
        let size = 8 + len; // SID length is a multiple of four.
        let insert = if kind == 0 {
            // Insert before existing allow ACEs, after existing deny ACEs.
            let mut pos = 8usize;
            while pos < used && unsafe { *acl.add(pos) } != 0 {
                pos += unsafe { read_unaligned(acl.add(pos + 2) as *const u16) } as usize;
            }
            pos
        } else { 8 };
        unsafe {
            copy(acl.add(insert), acl.add(insert + size), used - insert);
            *acl.add(insert) = kind;
            *acl.add(insert + 1) = e.inheritance as u8 | audit_flags;
            write_unaligned(acl.add(insert + 2) as *mut u16, size as u16);
            write_unaligned(acl.add(insert + 4) as *mut u32, mask);
            copy_nonoverlapping(sid.as_ptr(), acl.add(insert + 8), len);
        }
        used += size;
        ace_count += 1;
    }
    unsafe {
        write_unaligned(acl.add(4) as *mut u16, ace_count);
        *out = acl;
    }
    0
}

#[no_mangle]
pub unsafe extern "system" fn SetEntriesInAclW(count: u32, entries: *const ExplicitAccess, old: *const u8, out: *mut *mut u8) -> u32 {
    unsafe { make_entries(count, entries, old, out, false) }
}

#[no_mangle]
pub unsafe extern "system" fn SetEntriesInAclA(count: u32, entries: *const ExplicitAccess, old: *const u8, out: *mut *mut u8) -> u32 {
    unsafe { make_entries(count, entries, old, out, true) }
}
