// No C runtime: our own entry point, nothing linked by default.
fn main() {
    println!("cargo:rustc-cdylib-link-arg=/NODEFAULTLIB");
    println!("cargo:rustc-cdylib-link-arg=/ENTRY:DllMain");
    // Its own preferred base (win32/build.sh lists them all): the same
    // address in every process, as Windows' system DLLs are.
    println!("cargo:rustc-cdylib-link-arg=/BASE:0x7e0000000000");
    // Written in global_asm! (they carry their own unwind info).
    for f in [
        "KiUserExceptionDispatcher",
        "RtlRestoreContext",
        "memcpy",
        "memmove",
        "memset",
        "memcmp",
    ] {
        println!("cargo:rustc-cdylib-link-arg=/EXPORT:{f}");
    }
}
