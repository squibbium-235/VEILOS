//! Small Windows x64 MSVC STL ABI compatibility library for VEILOS.
//!
//! Rust implementation with no C object files or host MSVC runtime.
//! This implements the low-level thread/mutex/CV helpers, not C++ iostreams,
//! locales, exceptions, or the complete Microsoft C++ Standard Library.
#![no_std]
#![allow(non_snake_case)]

mod abi;
mod mutex;
mod condition;
mod threading;
mod time;
mod lockit;

#[no_mangle]
pub extern "system" fn DllMain(_module: usize, _reason: u32, _reserved: usize) -> i32 {
    1
}

// A no_std cdylib must provide its own panic handler. Do not unwind across
// the Windows ABI: end the process with a diagnostic failure code.
#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn ExitProcess(code: u32) -> !;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { ExitProcess(0xDEAD) }
}

// Required by the MSVC x64 ABI when floating-point code is linked.
#[no_mangle]
static _fltused: i32 = 0;
