fn main() {
    // When compiling for Windows MSVC target, statically link VC runtime and C startup
    // so the binary does not require vcruntime140.dll to be installed on the client machine.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:libvcruntimed.lib");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:vcruntime.lib");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:vcruntimed.lib");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:libcmtd.lib");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:msvcrt.lib");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:msvcrtd.lib");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:libucrt.lib");
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:libucrtd.lib");
        println!("cargo:rustc-link-arg=/DEFAULTLIB:libcmt.lib");
        println!("cargo:rustc-link-arg=/DEFAULTLIB:libvcruntime.lib");
        println!("cargo:rustc-link-arg=/DEFAULTLIB:ucrt.lib");
    }
}
