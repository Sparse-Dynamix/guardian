fn main() {
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
