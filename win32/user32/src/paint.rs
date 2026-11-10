//! Pixels and painting: each top-level window's client pixels (presented
//! to the kernel after drawing), DCs on them for a window and its children,
//! update rectangles, WM_ERASEBKGND and WM_PAINT; system colors and
//! metrics; the rectangle helpers.
//!
//! A child window draws into its top-level window's pixels, so when a
//! window is invalidated its children inside the area are too, and are
//! painted after it.

use alloc::vec::Vec;

use crate::message::{send, WM_ERASEBKGND, WM_NCPAINT, WM_PAINT};
use crate::{empty, intersect, state, union, Bool, Hwnd, Wnd};

const DESKTOP: Hwnd = 0x0001_0000;

/// Give a top-level window room for its client area. The pixels never
/// move while big enough (a DC may still point at them), and are kept
/// (leaked) when they must grow.
pub fn ensure_surface(w: &mut Wnd) {
    let (sw, sh) = w.surface_size();
    let (cw, ch) = (sw as usize, sh as usize);
    let rows = if w.stride == 0 { 0 } else { w.surface.len() / w.stride };
    if cw <= w.stride && ch <= rows {
        return;
    }
    let (sw, sh) = crate::screen_size();
    let stride = cw.max(sw as usize).max(w.stride);
    let rows = ch.max(sh as usize).max(rows);
    let old = core::mem::replace(&mut w.surface, alloc::vec![0x00FF_FFFF; stride * rows]);
    core::mem::forget(old);
    w.stride = stride;
}

/// Send the drawn part of a top-level window's pixels to the kernel.
pub fn present(root: Hwnd) {
    let mut s = state();
    let Some(w) = s.get_mut(root) else { return };
    let Some(d) = w.dirty.take() else { return };
    // A DC still out can go on drawing: what it covers stays due.
    for dc in DCS.lock().iter().filter(|dc| dc.1 == root) {
        w.dirty = Some(union(w.dirty, dc.2));
    }
    let (sw, sh) = w.surface_size();
    let d = intersect(d, [0, 0, sw, sh]);
    if !w.kernel || empty(d) {
        return;
    }
    let rect = [d[0], d[1], d[2] - d[0], d[3] - d[1]];
    unsafe { crate::VeilUserPresent(root, w.surface.as_ptr(), w.stride as u64, &rect) };
}

/// Present everything this thread has drawn.
pub fn present_all() {
    LAST_PRESENT.store(unsafe { GetTickCount() }, core::sync::atomic::Ordering::Relaxed);
    let tid = unsafe { crate::GetCurrentThreadId() };
    let roots: Vec<Hwnd> = state().windows.iter().filter(|w| w.tid == tid && w.dirty.is_some()).map(|w| w.hwnd).collect();
    for r in roots {
        present(r);
    }
}

/// Paints under way on this process's windows: nothing is presented until
/// they're done, so half-drawn windows (erased, not yet drawn) never show.
static PAINTING: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);
static LAST_PRESENT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetTickCount() -> u32;
}

/// For a program that draws without returning to its message loop: at most
/// one present a frame, and none in the middle of painting.
pub fn present_if_due() {
    use core::sync::atomic::Ordering;
    if PAINTING.load(Ordering::Relaxed) > 0 {
        return;
    }
    let now = unsafe { GetTickCount() };
    if now.wrapping_sub(LAST_PRESENT.load(Ordering::Relaxed)) < 16 {
        return;
    }
    if crate::message::paint_pending() {
        return;
    }
    present_all();
}

// -----| DCs |-----

/// DCs handed out by GetDC/BeginPaint: (hdc, top-level window, what it can
/// draw on).
static DCS: crate::dllrt::Lock<Vec<(u64, Hwnd, [i32; 4])>> = crate::dllrt::Lock::new(Vec::new());

/// A DC on `hwnd`'s client area, drawing only inside `clip` (client
/// coordinates, None: all of it); `frame`: on the whole window rectangle
/// instead (its non-client area).
fn make_dc(hwnd: Hwnd, clip: Option<[i32; 4]>, frame: bool) -> u64 {
    if hwnd == 0 || hwnd == DESKTOP {
        let (w, h) = crate::screen_size();
        return unsafe { crate::VeilGdiCreateDC(core::ptr::null_mut(), w, h, w as usize, 0, 0, core::ptr::null()) };
    }
    let mut s = state();
    let root = s.root(hwnd);
    let (mut ox, mut oy) = s.client_origin(hwnd);
    let mut area = s.visible_clip(hwnd);
    if frame {
        if let Some(w) = s.get(hwnd) {
            ox -= w.margins[0];
            oy -= w.margins[1];
            area = [ox, oy, ox + w.w, oy + w.h];
            if !w.top_level() {
                area = if w.visible { intersect(area, s.visible_clip(w.parent)) } else { [0, 0, 0, 0] };
            }
        }
    }
    if let Some(c) = clip {
        area = intersect(area, [c[0] + ox, c[1] + oy, c[2] + ox, c[3] + oy]);
    }
    let Some(r) = s.get_mut(root) else { return 0 };
    let (w, h) = r.surface_size();
    let (ptr, stride) = (r.surface.as_mut_ptr(), r.stride);
    if !empty(area) {
        r.dirty = Some(union(r.dirty, area));
    }
    drop(s);
    let hdc = unsafe { crate::VeilGdiCreateDC(ptr, w, h, stride, ox, oy, &area) };
    DCS.lock().push((hdc, root, area));
    hdc
}

fn release(hdc: u64) -> bool {
    let others = {
        let mut dcs = DCS.lock();
        let Some(i) = dcs.iter().position(|d| d.0 == hdc) else { return false };
        let root = dcs.swap_remove(i).1;
        dcs.iter().any(|d| d.1 == root)
    };
    unsafe { crate::DeleteDC(hdc) };
    // The message loop presents when the program goes idle. Not in the middle
    // of another DC's drawing (a paint measuring text through GetDC, say).
    if !others {
        present_if_due();
    }
    true
}

#[no_mangle]
pub extern "system" fn GetDC(hwnd: Hwnd) -> u64 {
    make_dc(hwnd, None, false)
}

#[no_mangle]
pub extern "system" fn GetDCEx(hwnd: Hwnd, _rgn: u64, _flags: u32) -> u64 {
    make_dc(hwnd, None, false)
}

#[no_mangle]
pub extern "system" fn GetWindowDC(hwnd: Hwnd) -> u64 {
    make_dc(hwnd, None, true)
}

#[no_mangle]
pub extern "system" fn ReleaseDC(_hwnd: Hwnd, hdc: u64) -> i32 {
    if !release(hdc) {
        // The screen DC isn't in the list.
        unsafe { crate::DeleteDC(hdc) };
    }
    1
}

// -----| update rectangles |-----

/// Add `rect` (client coordinates; None: all of it) to `hwnd`'s update
/// rectangle, and to its children's where they overlap. `hwnd` 0: every
/// window of this thread.
pub fn invalidate(hwnd: Hwnd, rect: Option<[i32; 4]>, erase: bool) {
    if hwnd == 0 || hwnd == DESKTOP {
        let tid = unsafe { crate::GetCurrentThreadId() };
        let roots: Vec<Hwnd> = state().windows.iter().filter(|w| w.parent == 0 && w.tid == tid).map(|w| w.hwnd).collect();
        for r in roots {
            invalidate(r, None, erase);
        }
        return;
    }
    let (children, tid) = {
        let mut s = state();
        let Some(w) = s.get_mut(hwnd) else { return };
        if !w.visible {
            return;
        }
        let all = [0, 0, w.client_w(), w.client_h()];
        let r = intersect(rect.unwrap_or(all), all);
        if empty(r) {
            return;
        }
        w.update = Some(union(w.update, r));
        w.erase |= erase;
        let tid = w.tid;
        let kids: Vec<(Hwnd, [i32; 4])> = s
            .windows
            .iter()
            .filter(|c| c.parent == hwnd && c.visible && !c.destroying)
            .map(|c| (c.hwnd, [r[0] - c.x - c.margins[0], r[1] - c.y - c.margins[1], r[2] - c.x - c.margins[0], r[3] - c.y - c.margins[1]]))
            .collect();
        (kids, tid)
    };
    for (c, r) in children {
        invalidate(c, Some(r), erase);
    }
    crate::message::wake(tid);
}

/// Send WM_ERASEBKGND now if `hwnd`'s update rectangle needs erasing.
pub fn erase_now(hwnd: Hwnd) {
    let update = {
        let mut s = state();
        let Some(w) = s.get_mut(hwnd) else { return };
        if !w.erase {
            return;
        }
        w.erase = false;
        w.update
    };
    let hdc = make_dc(hwnd, update, false);
    send(hwnd, WM_ERASEBKGND, hdc, 0);
    release(hdc);
}

/// UpdateWindow: WM_PAINT now for `hwnd` and its children that need it.
pub fn update_now(hwnd: Hwnd) {
    if state().get(hwnd).is_some_and(|w| w.update.is_some()) {
        send(hwnd, WM_PAINT, 0, 0);
    }
    let kids = state().children(hwnd);
    for k in kids {
        update_now(k);
    }
}

fn rect_arg(r: *const [i32; 4]) -> Option<[i32; 4]> {
    (!r.is_null()).then(|| unsafe { *r })
}

#[no_mangle]
pub extern "system" fn InvalidateRect(hwnd: Hwnd, r: *const [i32; 4], erase: Bool) -> Bool {
    if hwnd != 0 && state().get(hwnd).is_none() {
        return 0;
    }
    invalidate(hwnd, rect_arg(r), erase != 0);
    1
}

/// Regions come with G2: the whole window.
#[no_mangle]
pub extern "system" fn InvalidateRgn(hwnd: Hwnd, _rgn: u64, erase: Bool) -> Bool {
    InvalidateRect(hwnd, core::ptr::null(), erase)
}

fn validate(hwnd: Hwnd, r: Option<[i32; 4]>) -> Bool {
    let mut s = state();
    let Some(w) = s.get_mut(hwnd) else { return 0 };
    match (r, w.update) {
        (None, _) => w.update = None,
        (Some(r), Some(u)) if r[0] <= u[0] && r[1] <= u[1] && r[2] >= u[2] && r[3] >= u[3] => w.update = None,
        _ => {}
    }
    if w.update.is_none() {
        w.erase = false;
    }
    1
}

#[no_mangle]
pub extern "system" fn ValidateRect(hwnd: Hwnd, r: *const [i32; 4]) -> Bool {
    validate(hwnd, rect_arg(r))
}

#[no_mangle]
pub extern "system" fn ValidateRgn(hwnd: Hwnd, _rgn: u64) -> Bool {
    validate(hwnd, None)
}

#[no_mangle]
pub extern "system" fn GetUpdateRect(hwnd: Hwnd, out: *mut [i32; 4], erase: Bool) -> Bool {
    let u = state().get(hwnd).and_then(|w| w.update);
    if !out.is_null() {
        unsafe { *out = u.unwrap_or([0; 4]) };
    }
    if u.is_some() && erase != 0 {
        erase_now(hwnd);
    }
    u.is_some() as Bool
}

const RDW_INVALIDATE: u32 = 0x0001;
const RDW_ERASE: u32 = 0x0004;
const RDW_VALIDATE: u32 = 0x0008;
const RDW_ERASENOW: u32 = 0x0200;
const RDW_UPDATENOW: u32 = 0x0100;

#[no_mangle]
pub extern "system" fn RedrawWindow(hwnd: Hwnd, r: *const [i32; 4], _rgn: u64, flags: u32) -> Bool {
    let hwnd = if hwnd == 0 { DESKTOP } else { hwnd };
    if flags & RDW_INVALIDATE != 0 {
        invalidate(hwnd, rect_arg(r), flags & RDW_ERASE != 0);
    }
    if flags & RDW_VALIDATE != 0 {
        validate(hwnd, rect_arg(r));
    }
    if flags & (RDW_ERASENOW | RDW_UPDATENOW) != 0 && hwnd != DESKTOP {
        erase_now(hwnd);
    }
    if flags & RDW_UPDATENOW != 0 && hwnd != DESKTOP {
        update_now(hwnd);
    }
    1
}

// -----| BeginPaint / EndPaint |-----

/// PAINTSTRUCT: hdc, fErase, rcPaint, fRestore, fIncUpdate, reserved.
#[no_mangle]
pub extern "system" fn BeginPaint(hwnd: Hwnd, ps: *mut u8) -> u64 {
    PAINTING.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let (update, erase, framed) = {
        let mut s = state();
        let Some(w) = s.get_mut(hwnd) else { return 0 };
        let u = w.update.take().unwrap_or([0; 4]);
        let e = core::mem::replace(&mut w.erase, false);
        // Non-client parts of its own to draw: a child's border, scroll
        // bars, a popup's frame.
        (u, e, if w.top_level() { w.inset() != [0; 4] } else { w.margins != [0; 4] })
    };
    if framed {
        send(hwnd, WM_NCPAINT, 1, 0);
    }
    crate::keyboard::hide_caret_for_paint(hwnd);
    let hdc = make_dc(hwnd, Some(update), false);
    let not_erased = erase && send(hwnd, WM_ERASEBKGND, hdc, 0) == 0;
    if !ps.is_null() {
        unsafe {
            core::ptr::write_bytes(ps, 0, 72);
            *(ps as *mut u64) = hdc;
            *(ps.add(8) as *mut i32) = not_erased as i32;
            *(ps.add(12) as *mut [i32; 4]) = update;
        }
    }
    hdc
}

#[no_mangle]
pub extern "system" fn EndPaint(hwnd: Hwnd, ps: *const u8) -> Bool {
    if !ps.is_null() {
        release(unsafe { *(ps as *const u64) });
    }
    PAINTING.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    crate::keyboard::show_caret_after_paint(hwnd);
    1
}

/// WM_ERASEBKGND's DefWindowProc: the class background brush over what
/// the DC may draw. True if there was one.
pub fn erase_background(hwnd: Hwnd, hdc: u64) -> bool {
    let brush = {
        let s = state();
        let Some(w) = s.get(hwnd) else { return false };
        s.classes[w.class].brush
    };
    if brush == 0 {
        return false;
    }
    let mut r = [0i32; 4];
    unsafe { crate::GetClipBox(hdc, &mut r) };
    FillRect(hdc, &r, brush);
    true
}

/// WM_NCPAINT's DefWindowProc for a child window: its border.
/// WM_NCPAINT's DefWindowProc: the borders it draws itself (a child's,
/// or a popup's; the desktop frames other top-level windows) and the
/// standard scroll bars.
pub fn paint_frame(hwnd: Hwnd) {
    let Some((w, h, style, ex, own_border)) =
        state().get(hwnd).map(|w| (w.w, w.h, w.style, w.ex_style, !w.top_level() || w.popup))
    else {
        return;
    };
    let hdc = make_dc(hwnd, None, true);
    if own_border {
        let mut inset = 0;
        if ex & crate::window::WS_EX_CLIENTEDGE != 0 {
            frame(hdc, [0, 0, w, h], GetSysColorBrush(16));
            frame(hdc, [1, 1, w - 1, h - 1], GetSysColorBrush(21));
            inset = 2;
        }
        if style & crate::window::WS_DLGFRAME != 0 && style & crate::window::WS_CHILD == 0 {
            // A popup dialog's raised frame.
            frame(hdc, [0, 0, w, h], GetSysColorBrush(21));
            frame(hdc, [1, 1, w - 1, h - 1], GetSysColorBrush(20));
            frame(hdc, [2, 2, w - 2, h - 2], GetSysColorBrush(15));
        } else if style & crate::window::WS_BORDER != 0 {
            frame(hdc, [inset, inset, w - inset, h - inset], GetSysColorBrush(6));
        }
    }
    crate::scroll::paint_bars(hwnd, hdc);
    crate::menu::paint_bar(hwnd, hdc);
    release(hdc);
}

// -----| filling |-----

/// A brush argument: a brush, or a system color index + 1.
fn brush_of(b: u64) -> u64 {
    if b != 0 && b <= 31 { GetSysColorBrush(b as i32 - 1) } else { b }
}

#[no_mangle]
pub extern "system" fn FillRect(hdc: u64, r: *const [i32; 4], brush: u64) -> i32 {
    let Some(r) = rect_arg(r) else { return 0 };
    let old = unsafe { crate::SelectObject(hdc, brush_of(brush)) };
    unsafe { crate::PatBlt(hdc, r[0], r[1], r[2] - r[0], r[3] - r[1], 0x00F0_0021) };
    unsafe { crate::SelectObject(hdc, old) };
    1
}

fn frame(hdc: u64, r: [i32; 4], brush: u64) {
    let old = unsafe { crate::SelectObject(hdc, brush) };
    let (w, h) = (r[2] - r[0], r[3] - r[1]);
    if w > 0 && h > 0 {
        unsafe {
            crate::PatBlt(hdc, r[0], r[1], w, 1, 0x00F0_0021);
            crate::PatBlt(hdc, r[0], r[3] - 1, w, 1, 0x00F0_0021);
            crate::PatBlt(hdc, r[0], r[1], 1, h, 0x00F0_0021);
            crate::PatBlt(hdc, r[2] - 1, r[1], 1, h, 0x00F0_0021);
        }
    }
    unsafe { crate::SelectObject(hdc, old) };
}

#[no_mangle]
pub extern "system" fn FrameRect(hdc: u64, r: *const [i32; 4], brush: u64) -> i32 {
    let Some(r) = rect_arg(r) else { return 0 };
    frame(hdc, r, brush_of(brush));
    1
}

#[no_mangle]
pub extern "system" fn InvertRect(hdc: u64, r: *const [i32; 4]) -> Bool {
    let Some(r) = rect_arg(r) else { return 0 };
    unsafe { crate::PatBlt(hdc, r[0], r[1], r[2] - r[0], r[3] - r[1], 0x0055_0009) }
}

// -----| DrawText |-----

const DT_CENTER: u32 = 0x1;
const DT_RIGHT: u32 = 0x2;
const DT_VCENTER: u32 = 0x4;
const DT_BOTTOM: u32 = 0x8;
const DT_WORDBREAK: u32 = 0x10;
const DT_SINGLELINE: u32 = 0x20;
const DT_EXPANDTABS: u32 = 0x40;
const DT_TABSTOP: u32 = 0x80;
const DT_NOCLIP: u32 = 0x100;
const DT_EXTERNALLEADING: u32 = 0x200;
const DT_CALCRECT: u32 = 0x400;
const DT_NOPREFIX: u32 = 0x800;
const DT_PATH_ELLIPSIS: u32 = 0x4000;
const DT_END_ELLIPSIS: u32 = 0x8000;
const DT_MODIFYSTRING: u32 = 0x10000;
const DT_WORD_ELLIPSIS: u32 = 0x40000;
const DT_HIDEPREFIX: u32 = 0x10_0000;
const DT_PREFIXONLY: u32 = 0x20_0000;

const SPACE: u16 = b' ' as u16;

fn width(hdc: u64, s: &[u16]) -> i32 {
    let mut sz = [0i32; 2];
    unsafe { crate::GetTextExtentPoint32W(hdc, s.as_ptr(), s.len() as i32, &mut sz) };
    sz[0]
}

/// A line of DrawText's output: its text, and the index in it of the
/// character a '&' prefix underlines.
struct Line {
    text: Vec<u16>,
    mnemonic: Option<usize>,
}

/// Remove '&' prefixes ("&&" is a '&'), noting what the last one marks.
fn strip_prefixes(text: &[u16]) -> (Vec<u16>, Option<usize>) {
    let mut out = Vec::with_capacity(text.len());
    let mut mark = None;
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'&' as u16 && i + 1 < text.len() {
            i += 1;
            if text[i] != b'&' as u16 {
                mark = Some(out.len());
            }
        }
        out.push(text[i]);
        i += 1;
    }
    (out, mark)
}

/// Tabs to spaces, up to every `stop`th column.
fn expand_tabs(text: &[u16], stop: usize) -> Vec<u16> {
    let mut out = Vec::with_capacity(text.len());
    for &c in text {
        if c == b'\t' as u16 {
            let n = stop - out.len() % stop;
            out.extend(core::iter::repeat_n(SPACE, n));
        } else {
            out.push(c);
        }
    }
    out
}

/// Break `text` into lines no wider than `max`, at spaces (a word longer
/// than a line stays whole).
fn wrap(hdc: u64, text: &[u16], max: i32) -> Vec<Vec<u16>> {
    let mut lines = Vec::new();
    let mut start = 0;
    while start < text.len() {
        // The longest run of whole words from `start` that fits.
        let mut end = start;
        let mut i = start;
        loop {
            while i < text.len() && text[i] != SPACE {
                i += 1;
            }
            if end > start && width(hdc, &text[start..i]) > max {
                break;
            }
            end = i;
            if i >= text.len() {
                break;
            }
            i += 1;
        }
        let mut line_end = end;
        while line_end > start && text[line_end - 1] == SPACE {
            line_end -= 1;
        }
        lines.push(text[start..line_end].to_vec());
        start = end;
        while start < text.len() && text[start] == SPACE {
            start += 1;
        }
    }
    if lines.is_empty() {
        lines.push(Vec::new());
    }
    lines
}

/// `text` shortened with "..." to fit `max`: at the end, at a word end,
/// or (`path`) keeping the part after the last backslash.
fn ellipsize(hdc: u64, text: &[u16], max: i32, path: bool, word: bool) -> Vec<u16> {
    if width(hdc, text) <= max {
        return text.to_vec();
    }
    let dots: Vec<u16> = "...".encode_utf16().collect();
    if path {
        if let Some(slash) = text.iter().rposition(|&c| c == b'\\' as u16) {
            let tail = &text[slash..];
            for keep in (0..slash).rev() {
                let candidate: Vec<u16> = text[..keep].iter().chain(&dots).chain(tail).copied().collect();
                if width(hdc, &candidate) <= max {
                    return candidate;
                }
            }
            let candidate: Vec<u16> = dots.iter().chain(tail).copied().collect();
            return candidate;
        }
    }
    for keep in (0..text.len()).rev() {
        if word && keep > 0 && text[keep] != SPACE && text[keep - 1] != SPACE {
            continue;
        }
        let mut head = text[..keep].to_vec();
        while head.last() == Some(&SPACE) {
            head.pop();
        }
        head.extend_from_slice(&dots);
        if width(hdc, &head) <= max {
            return head;
        }
    }
    dots
}

/// DrawText: lines, word breaks, tabs, ellipses, '&' prefixes, alignment,
/// clipping and DT_CALCRECT. The height, and the shortened text for
/// DT_MODIFYSTRING.
fn draw_text(hdc: u64, text: &[u16], r: *mut [i32; 4], flags: u32) -> (i32, Option<Vec<u16>>) {
    let Some(rect) = rect_arg(r) else { return (0, None) };
    let max_w = rect[2] - rect[0];
    let mut tm = [0u8; 60];
    unsafe { crate::GetTextMetricsW(hdc, tm.as_mut_ptr()) };
    let tm_height = i32::from_le_bytes(tm[0..4].try_into().unwrap());
    let tm_ascent = i32::from_le_bytes(tm[4..8].try_into().unwrap());
    let ext_leading = i32::from_le_bytes(tm[16..20].try_into().unwrap());
    let line_h = tm_height + if flags & DT_EXTERNALLEADING != 0 { ext_leading } else { 0 };

    let tabbed = if flags & DT_EXPANDTABS != 0 {
        let stop = if flags & DT_TABSTOP != 0 { ((flags >> 8) & 0xFF).max(1) as usize } else { 8 };
        expand_tabs(text, stop)
    } else {
        text.to_vec()
    };
    let prefixes = flags & DT_NOPREFIX == 0;
    let raw_lines: Vec<&[u16]> = if flags & DT_SINGLELINE != 0 {
        alloc::vec![&tabbed[..]]
    } else {
        tabbed.split(|&c| c == b'\n' as u16).map(|l| l.strip_suffix(&[b'\r' as u16]).unwrap_or(l)).collect()
    };
    let mut lines: Vec<Line> = Vec::new();
    for raw in raw_lines {
        let raw: Vec<u16> = if flags & DT_SINGLELINE != 0 { raw.iter().copied().filter(|&c| c != 13 && c != 10).collect() } else { raw.to_vec() };
        let (clean, mark) = if prefixes { strip_prefixes(&raw) } else { (raw, None) };
        if flags & DT_WORDBREAK != 0 && flags & DT_SINGLELINE == 0 && max_w > 0 {
            // The mnemonic stays with the line that holds it.
            let mut pos = 0;
            for piece in wrap(hdc, &clean, max_w) {
                let at = clean[pos..].windows(piece.len().max(1)).position(|w| w == &piece[..]).map_or(pos, |p| p + pos);
                let m = mark.filter(|&m| m >= at && m < at + piece.len()).map(|m| m - at);
                pos = at + piece.len();
                lines.push(Line { text: piece, mnemonic: m });
            }
        } else {
            lines.push(Line { text: clean, mnemonic: mark });
        }
    }
    let mut modified = None;
    if flags & (DT_END_ELLIPSIS | DT_PATH_ELLIPSIS | DT_WORD_ELLIPSIS) != 0 {
        for line in lines.iter_mut() {
            let short = ellipsize(hdc, &line.text, max_w, flags & DT_PATH_ELLIPSIS != 0, flags & DT_WORD_ELLIPSIS != 0);
            if short != line.text {
                line.text = short;
                line.mnemonic = line.mnemonic.filter(|&m| m + 3 < line.text.len());
                if flags & DT_MODIFYSTRING != 0 {
                    modified = Some(line.text.clone());
                }
            }
        }
    }
    let widths: Vec<i32> = lines.iter().map(|l| width(hdc, &l.text)).collect();
    let total_h = line_h * lines.len() as i32;
    if flags & DT_CALCRECT != 0 {
        let w = widths.iter().copied().max().unwrap_or(0);
        unsafe {
            if flags & DT_WORDBREAK == 0 || w > max_w || max_w <= 0 {
                (*r)[2] = rect[0] + w;
            }
            (*r)[3] = rect[1] + total_h;
        }
        return (total_h, modified);
    }
    let mut y = rect[1];
    let mut ret = total_h;
    if flags & DT_SINGLELINE != 0 && flags & (DT_VCENTER | DT_BOTTOM) != 0 {
        y = if flags & DT_VCENTER != 0 { rect[1] + (rect[3] - rect[1] - line_h) / 2 } else { rect[3] - line_h };
        ret = y - rect[1] + line_h;
    }
    let clip = flags & DT_NOCLIP == 0;
    if clip {
        unsafe {
            crate::SaveDC(hdc);
            crate::IntersectClipRect(hdc, rect[0], rect[1], rect[2], rect[3]);
        }
    }
    let old_align = unsafe { crate::SetTextAlign(hdc, 0) };
    let underline = prefixes && flags & DT_HIDEPREFIX == 0;
    for (line, w) in lines.iter().zip(&widths) {
        let x = if flags & DT_CENTER != 0 {
            rect[0] + (max_w - w) / 2
        } else if flags & DT_RIGHT != 0 {
            rect[2] - w
        } else {
            rect[0]
        };
        if flags & DT_PREFIXONLY == 0 {
            unsafe { crate::TextOutW(hdc, x, y, line.text.as_ptr(), line.text.len() as i32) };
        }
        if let (true, Some(m)) = (underline, line.mnemonic) {
            let ux = x + width(hdc, &line.text[..m]);
            let uw = width(hdc, &line.text[m..m + 1]);
            let brush = unsafe { crate::CreateSolidBrush(crate::GetTextColor(hdc)) };
            let u = [ux, y + tm_ascent + 1, ux + uw, y + tm_ascent + 2];
            FillRect(hdc, &u, brush);
            unsafe { crate::DeleteObject(brush) };
        }
        y += line_h;
    }
    unsafe { crate::SetTextAlign(hdc, old_align) };
    if clip {
        unsafe { crate::RestoreDC(hdc, -1) };
    }
    (ret, modified)
}

#[no_mangle]
pub unsafe extern "system" fn DrawTextW(hdc: u64, s: *mut u16, n: i32, r: *mut [i32; 4], flags: u32) -> i32 {
    let text = if n < 0 { unsafe { crate::wstr(s) } } else { unsafe { core::slice::from_raw_parts(s, n as usize) }.to_vec() };
    let (h, modified) = draw_text(hdc, &text, r, flags);
    if let Some(m) = modified {
        // The buffer has room for the text plus four characters.
        unsafe { crate::copy_out(&m, s, text.len() + 5) };
    }
    h
}

#[no_mangle]
pub unsafe extern "system" fn DrawTextA(hdc: u64, s: *mut u8, n: i32, r: *mut [i32; 4], flags: u32) -> i32 {
    let text = unsafe { crate::from_ansi(s, n) };
    let len = if n < 0 { (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count() } else { n as usize };
    let (h, modified) = draw_text(hdc, &text, r, flags);
    if let Some(m) = modified {
        unsafe { crate::copy_out(&crate::to_ansi(&m), s, len + 5) };
    }
    h
}

#[no_mangle]
pub unsafe extern "system" fn DrawTextExW(hdc: u64, s: *mut u16, n: i32, r: *mut [i32; 4], flags: u32, _p: usize) -> i32 {
    unsafe { DrawTextW(hdc, s, n, r, flags) }
}

#[no_mangle]
pub unsafe extern "system" fn DrawTextExA(hdc: u64, s: *mut u8, n: i32, r: *mut [i32; 4], flags: u32, _p: usize) -> i32 {
    unsafe { DrawTextA(hdc, s, n, r, flags) }
}

// -----| system colors and metrics |-----

/// Windows 10's default colors (COLORREF), COLOR_SCROLLBAR to COLOR_MENUBAR.
const SYS_COLORS: [u32; 31] = [
    0xC8C8C8, 0x000000, 0xD1B499, 0xDBCDBF, 0xF0F0F0, 0xFFFFFF, 0x646464, 0x000000, 0x000000, 0x000000,
    0xB4B4B4, 0xFCF7F4, 0xABABAB, 0xD77800, 0xFFFFFF, 0xF0F0F0, 0xA0A0A0, 0x6D6D6D, 0x000000, 0x000000,
    0xFFFFFF, 0x696969, 0xE3E3E3, 0x000000, 0xE1FFFF, 0x000000, 0xCC6600, 0xEAD1B9, 0xF2E4D7, 0xFF9933,
    0xF0F0F0,
];

static SYS_BRUSHES: crate::dllrt::Lock<[u64; 31]> = crate::dllrt::Lock::new([0; 31]);

#[no_mangle]
pub extern "system" fn GetSysColor(index: i32) -> u32 {
    SYS_COLORS.get(index as usize).copied().unwrap_or(0)
}

#[no_mangle]
pub extern "system" fn GetSysColorBrush(index: i32) -> u64 {
    let Some(&color) = SYS_COLORS.get(index as usize) else { return 0 };
    let mut b = SYS_BRUSHES.lock();
    if b[index as usize] == 0 {
        b[index as usize] = unsafe { crate::CreateSolidBrush(color) };
    }
    b[index as usize]
}

#[no_mangle]
pub extern "system" fn GetSystemMetrics(index: i32) -> i32 {
    let (sw, sh) = crate::screen_size();
    match index {
        0 | 16 | 61 | 78 => sw, // SM_CXSCREEN, CXFULLSCREEN, CXMAXIMIZED, CXVIRTUALSCREEN
        1 | 62 | 79 => sh,
        17 => sh - 23,          // SM_CYFULLSCREEN
        2 | 3 | 9 | 10 | 20 | 21 => 17, // scroll bars and thumbs
        4 => 23,                // SM_CYCAPTION
        5 | 6 => 1,             // SM_CXBORDER, CYBORDER
        7 | 8 => 3,             // SM_CXFIXEDFRAME
        11 | 12 | 13 | 14 => 32, // icons, cursors
        15 => 20,               // SM_CYMENU
        19 => 1,                // SM_MOUSEPRESENT
        28 | 34 => 136,         // SM_CXMIN, CXMINTRACK
        29 | 35 => 39,          // SM_CYMIN, CYMINTRACK
        30 => 36,               // SM_CXSIZE
        31 => 22,               // SM_CYSIZE
        32 | 33 => 4,           // SM_CXFRAME
        36 | 37 => 4,           // double-click area
        38 | 39 => 75,          // icon spacing
        43 => 3,                // SM_CMOUSEBUTTONS
        45 | 46 => 2,           // SM_CXEDGE
        49 | 50 => 16,          // small icons
        51 => 23,               // SM_CYSMCAPTION
        59 => sw + 12,          // SM_CXMAXTRACK
        60 => sh + 12,
        80 => 1,                // SM_CMONITORS
        81 => 1,                // SM_SAMEDISPLAYFORMAT
        92 => 4,                // SM_CXPADDEDBORDER
        _ => 0,
    }
}

#[no_mangle]
pub extern "system" fn GetSystemMetricsForDpi(index: i32, _dpi: u32) -> i32 {
    GetSystemMetrics(index)
}

/// A LOGFONTW of Segoe UI (Windows' interface font), `height` pixels.
fn ui_font(out: *mut u8, height: i32, weight: i32) {
    unsafe {
        core::ptr::write_bytes(out, 0, 92);
        *(out as *mut i32) = height;
        *(out.add(16) as *mut i32) = weight;
        *out.add(23) = 1; // DEFAULT_CHARSET
        *out.add(26) = 5; // CLEARTYPE_QUALITY
        for (i, c) in "Segoe UI".encode_utf16().enumerate() {
            *(out.add(28 + 2 * i) as *mut u16) = c;
        }
    }
}

#[no_mangle]
pub extern "system" fn SystemParametersInfoW(action: u32, p: u32, out: *mut u8, _ini: u32) -> Bool {
    let put32 = |v: u32| {
        if !out.is_null() {
            unsafe { *(out as *mut u32) = v };
        }
        1
    };
    match action {
        0x30 => {
            // SPI_GETWORKAREA: below the desktop's panel.
            let (w, h) = crate::screen_size();
            unsafe { *(out as *mut [i32; 4]) = [0, 0, w, h] };
            1
        }
        // SPI_GETNONCLIENTMETRICS: Windows 10's sizes and fonts.
        0x29 => {
            if out.is_null() {
                return 0;
            }
            let size = unsafe { *(out as *const u32) }.max(500) as usize;
            unsafe { core::ptr::write_bytes(out.add(4), 0, size.min(504) - 4) };
            let ints = [1, 17, 17, 22, 22];
            for (i, v) in ints.iter().enumerate() {
                unsafe { *(out.add(4 + i * 4) as *mut i32) = *v };
            }
            ui_font(unsafe { out.add(24) }, -12, 400); // caption font
            unsafe {
                *(out.add(116) as *mut i32) = 22;
                *(out.add(120) as *mut i32) = 22;
            }
            ui_font(unsafe { out.add(124) }, -12, 400); // small caption
            unsafe {
                *(out.add(216) as *mut i32) = 19;
                *(out.add(220) as *mut i32) = 19;
            }
            ui_font(unsafe { out.add(224) }, -12, 400); // menu
            ui_font(unsafe { out.add(316) }, -12, 400); // status
            ui_font(unsafe { out.add(408) }, -12, 400); // message
            if size >= 504 {
                unsafe { *(out.add(500) as *mut i32) = 4 }; // iPaddedBorderWidth
            }
            1
        }
        // SPI_GETICONTITLELOGFONT
        0x1F => {
            ui_font(out, -12, 400);
            1
        }
        // SPI_GETWHEELSCROLLLINES, SPI_GETWHEELSCROLLCHARS
        0x68 | 0x6C => put32(3),
        // SPI_GETFONTSMOOTHING, SPI_GETKEYBOARDCUES, SPI_GETDRAGFULLWINDOWS
        0x4A | 0x100A | 0x26 => put32(1),
        // SPI_GETFLATMENU, SPI_GETSCREENREADER, SPI_GETMENUANIMATION,
        // SPI_GETCLIENTAREAANIMATION, SPI_GETCLEARTYPE
        0x1022 | 0x46 | 0x1002 | 0x1042 | 0x1048 => put32(0),
        // SPI_GETHIGHCONTRAST: off.
        0x42 => {
            if !out.is_null() {
                unsafe {
                    *(out.add(4) as *mut u32) = 0;
                    *(out.add(8) as *mut u64) = 0;
                }
            }
            1
        }
        // SPI_GETKEYBOARDDELAY, SPI_GETKEYBOARDSPEED, SPI_GETMENUSHOWDELAY
        0x16 => put32(1),
        0x0A => put32(31),
        0x6A => put32(400),
        // SPI_GETFOCUSBORDERWIDTH/HEIGHT, SPI_GETCARETWIDTH
        0x200E | 0x2010 | 0x2006 => put32(1),
        _ => {
            let _ = p;
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn SystemParametersInfoForDpi(action: u32, p: u32, out: *mut u8, ini: u32, _dpi: u32) -> Bool {
    SystemParametersInfoW(action, p, out, ini)
}

// -----| the monitor: one, the screen |-----

const MONITOR: u64 = 0x0001_0001;

#[no_mangle]
pub extern "system" fn MonitorFromWindow(_hwnd: Hwnd, _flags: u32) -> u64 {
    MONITOR
}

#[no_mangle]
pub extern "system" fn MonitorFromPoint(_x: i64, _flags: u32) -> u64 {
    MONITOR
}

#[no_mangle]
pub extern "system" fn MonitorFromRect(_r: *const [i32; 4], _flags: u32) -> u64 {
    MONITOR
}

/// MONITORINFO(EX): size, monitor and work rectangles, flags, (device).
fn monitor_info(out: *mut u8, wide: bool) -> Bool {
    if out.is_null() {
        return 0;
    }
    let size = unsafe { *(out as *const u32) };
    let (w, h) = crate::screen_size();
    unsafe {
        *(out.add(4) as *mut [i32; 4]) = [0, 0, w, h];
        *(out.add(20) as *mut [i32; 4]) = [0, 0, w, h];
        *(out.add(36) as *mut u32) = 1; // MONITORINFOF_PRIMARY
    }
    if size > 40 {
        let name = "\\\\.\\DISPLAY1";
        for (i, c) in name.encode_utf16().chain(core::iter::once(0)).enumerate() {
            unsafe {
                if wide {
                    *(out.add(40 + i * 2) as *mut u16) = c;
                } else {
                    *out.add(40 + i) = c as u8;
                }
            }
        }
    }
    1
}

#[no_mangle]
pub extern "system" fn GetMonitorInfoW(_mon: u64, out: *mut u8) -> Bool {
    monitor_info(out, true)
}

#[no_mangle]
pub extern "system" fn GetMonitorInfoA(_mon: u64, out: *mut u8) -> Bool {
    monitor_info(out, false)
}

#[no_mangle]
pub extern "system" fn EnumDisplayMonitors(_hdc: u64, _clip: *const [i32; 4], proc: usize, lp: i64) -> Bool {
    if proc == 0 {
        return 0;
    }
    let (w, h) = crate::screen_size();
    let r = [0, 0, w, h];
    let f: unsafe extern "system" fn(u64, u64, *const [i32; 4], i64) -> Bool = unsafe { core::mem::transmute(proc) };
    unsafe { f(MONITOR, 0, &r, lp) };
    1
}

#[no_mangle]
pub extern "system" fn SystemParametersInfoA(action: u32, p: u32, out: *mut u8, ini: u32) -> Bool {
    SystemParametersInfoW(action, p, out, ini)
}

#[no_mangle]
pub extern "system" fn GetDpiForWindow(_hwnd: Hwnd) -> u32 {
    96
}

#[no_mangle]
pub extern "system" fn GetDpiForSystem() -> u32 {
    96
}

// The compositor currently renders at 96 DPI.  DPI_AWARENESS_CONTEXT is
// a pseudo-handle; preserve Windows' per-process/per-thread selections even
// though scaling is not implemented yet.
const DPI_UNAWARE: i64 = -1;
const DPI_SYSTEM_AWARE: i64 = -2;
static PROCESS_DPI_CONTEXT: core::sync::atomic::AtomicI64 =
    core::sync::atomic::AtomicI64::new(DPI_SYSTEM_AWARE);
static THREAD_DPI_SLOT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(u32::MAX);
const DPI_SLOT_ALLOCATING: u32 = u32::MAX - 1;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn TlsAlloc() -> u32;
    fn TlsGetValue(index: u32) -> usize;
    fn TlsSetValue(index: u32, value: usize) -> Bool;
}

fn valid_dpi_context(context: i64) -> bool {
    matches!(context, -5 | -4 | -3 | DPI_SYSTEM_AWARE | DPI_UNAWARE)
}

fn dpi_thread_slot() -> Option<u32> {
    use core::sync::atomic::Ordering;
    loop {
        let value = THREAD_DPI_SLOT.load(Ordering::Acquire);
        if value < DPI_SLOT_ALLOCATING { return Some(value); }
        if value == DPI_SLOT_ALLOCATING { core::hint::spin_loop(); continue; }
        if THREAD_DPI_SLOT.compare_exchange(u32::MAX, DPI_SLOT_ALLOCATING, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            let index = unsafe { TlsAlloc() };
            THREAD_DPI_SLOT.store(index, Ordering::Release);
            return if index == u32::MAX { None } else { Some(index) };
        }
    }
}

#[no_mangle]
pub extern "system" fn SetProcessDPIAware() -> Bool {
    PROCESS_DPI_CONTEXT.store(DPI_SYSTEM_AWARE, core::sync::atomic::Ordering::Release);
    1
}

#[no_mangle]
pub extern "system" fn IsProcessDPIAware() -> Bool {
    (PROCESS_DPI_CONTEXT.load(core::sync::atomic::Ordering::Acquire) != DPI_UNAWARE) as Bool
}

#[no_mangle]
pub extern "system" fn SetProcessDpiAwarenessContext(context: i64) -> Bool {
    if !valid_dpi_context(context) { crate::set_error(87); return 0; }
    PROCESS_DPI_CONTEXT.store(context, core::sync::atomic::Ordering::Release);
    1
}

#[no_mangle]
pub extern "system" fn GetThreadDpiAwarenessContext() -> i64 {
    if let Some(index) = dpi_thread_slot() {
        let value = unsafe { TlsGetValue(index) } as i64;
        if valid_dpi_context(value) { return value; }
    }
    PROCESS_DPI_CONTEXT.load(core::sync::atomic::Ordering::Acquire)
}

#[no_mangle]
pub extern "system" fn SetThreadDpiAwarenessContext(context: i64) -> i64 {
    if !valid_dpi_context(context) { crate::set_error(87); return 0; }
    let previous = GetThreadDpiAwarenessContext();
    let Some(index) = dpi_thread_slot() else { crate::set_error(8); return 0; };
    if unsafe { TlsSetValue(index, context as usize) } == 0 { return 0; }
    previous
}

/// Windows' pseudo-handle DPI contexts have no extra informational flags.
/// In this implementation a context is one of those five canonical values.
#[no_mangle]
pub extern "system" fn AreDpiAwarenessContextsEqual(a: i64, b: i64) -> Bool {
    (valid_dpi_context(a) && valid_dpi_context(b) && a == b) as Bool
}

#[no_mangle]
pub extern "system" fn GetAwarenessFromDpiAwarenessContext(context: i64) -> i32 {
    match context {
        DPI_UNAWARE => 0,
        DPI_SYSTEM_AWARE => 1,
        -3 | -4 | -5 => 2,
        _ => -1, // DPI_AWARENESS_INVALID
    }
}

#[no_mangle]
pub extern "system" fn IsValidDpiAwarenessContext(context: i64) -> Bool {
    valid_dpi_context(context) as Bool
}

#[no_mangle]
pub extern "system" fn GetWindowDpiAwarenessContext(_hwnd: Hwnd) -> i64 {
    PROCESS_DPI_CONTEXT.load(core::sync::atomic::Ordering::Acquire)
}

// -----| the pointer, message boxes (dialogs: G3) |-----

#[no_mangle]
pub extern "system" fn GetCursorPos(out: *mut [i32; 2]) -> Bool {
    if out.is_null() {
        return 0;
    }
    unsafe { (crate::VeilUserQuery(1, out) == 0) as Bool }
}

#[no_mangle]
pub extern "system" fn SetCursorPos(_x: i32, _y: i32) -> Bool {
    1
}

#[no_mangle]
pub extern "system" fn ClipCursor(_r: *const [i32; 4]) -> Bool {
    1
}

#[no_mangle]
pub extern "system" fn MessageBeep(_kind: u32) -> Bool {
    1
}

// -----| rectangles |-----

type Rect = [i32; 4];

#[no_mangle]
pub extern "system" fn SetRect(r: *mut Rect, l: i32, t: i32, rr: i32, b: i32) -> Bool {
    if r.is_null() {
        return 0;
    }
    unsafe { *r = [l, t, rr, b] };
    1
}

#[no_mangle]
pub extern "system" fn SetRectEmpty(r: *mut Rect) -> Bool {
    SetRect(r, 0, 0, 0, 0)
}

#[no_mangle]
pub extern "system" fn CopyRect(d: *mut Rect, s: *const Rect) -> Bool {
    if d.is_null() || s.is_null() {
        return 0;
    }
    unsafe { *d = *s };
    1
}

#[no_mangle]
pub extern "system" fn OffsetRect(r: *mut Rect, dx: i32, dy: i32) -> Bool {
    if r.is_null() {
        return 0;
    }
    unsafe {
        (*r)[0] += dx;
        (*r)[1] += dy;
        (*r)[2] += dx;
        (*r)[3] += dy;
    }
    1
}

#[no_mangle]
pub extern "system" fn InflateRect(r: *mut Rect, dx: i32, dy: i32) -> Bool {
    if r.is_null() {
        return 0;
    }
    unsafe {
        (*r)[0] -= dx;
        (*r)[1] -= dy;
        (*r)[2] += dx;
        (*r)[3] += dy;
    }
    1
}

#[no_mangle]
pub extern "system" fn IsRectEmpty(r: *const Rect) -> Bool {
    rect_arg(r).is_none_or(empty) as Bool
}

#[no_mangle]
pub extern "system" fn EqualRect(a: *const Rect, b: *const Rect) -> Bool {
    (!a.is_null() && !b.is_null() && unsafe { *a == *b }) as Bool
}

#[no_mangle]
pub extern "system" fn PtInRect(r: *const Rect, x: i32, y: i32) -> Bool {
    rect_arg(r).is_some_and(|r| x >= r[0] && x < r[2] && y >= r[1] && y < r[3]) as Bool
}

#[no_mangle]
pub extern "system" fn IntersectRect(d: *mut Rect, a: *const Rect, b: *const Rect) -> Bool {
    let (Some(a), Some(b)) = (rect_arg(a), rect_arg(b)) else { return 0 };
    let r = intersect(a, b);
    let r = if empty(r) { [0; 4] } else { r };
    SetRect(d, r[0], r[1], r[2], r[3]);
    (!empty(r)) as Bool
}

#[no_mangle]
pub extern "system" fn UnionRect(d: *mut Rect, a: *const Rect, b: *const Rect) -> Bool {
    let (Some(a), Some(b)) = (rect_arg(a), rect_arg(b)) else { return 0 };
    let r = match (empty(a), empty(b)) {
        (true, true) => [0; 4],
        (true, false) => b,
        (false, true) => a,
        _ => union(Some(a), b),
    };
    SetRect(d, r[0], r[1], r[2], r[3]);
    (!empty(r)) as Bool
}
