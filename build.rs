#[path = "build/apply_proxyapi_patch.rs"]
mod apply_proxyapi_patch;

fn main() {
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    apply_proxyapi_patch::apply_if_needed_build(&manifest_dir)
        .expect("failed to apply proxyapi patch");

    println!("cargo:rerun-if-changed=build/apply_proxyapi_patch.rs");

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    }
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path");
    }
    // Frida's static lib embeds OpenSSL; proxyapi also links openssl-sys on Windows.
    #[cfg(windows)]
    {
        println!("cargo:rustc-link-arg=/FORCE:MULTIPLE");
    }
}
