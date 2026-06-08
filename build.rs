use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const MKCERT_VERSION: &str = "v1.4.4";

fn main() {
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    }
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path");
    }
    #[cfg(windows)]
    {
        println!("cargo:rustc-link-arg=/FORCE:MULTIPLE");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");

    if let Err(e) = fetch_mkcert() {
        panic!("failed to fetch mkcert for embedding: {e}");
    }
}

fn mkcert_platform() -> Option<(&'static str, &'static str)> {
    let os = env::var("CARGO_CFG_TARGET_OS").ok()?;
    let arch = env::var("CARGO_CFG_TARGET_ARCH").ok()?;
    match (os.as_str(), arch.as_str()) {
        ("linux", "x86_64") => Some(("linux", "amd64")),
        ("linux", "aarch64") => Some(("linux", "arm64")),
        ("macos", "x86_64") => Some(("darwin", "amd64")),
        ("macos", "aarch64") => Some(("darwin", "arm64")),
        ("windows", "x86_64") => Some(("windows", "amd64")),
        _ => None,
    }
}

fn fetch_mkcert() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let (os, arch) = mkcert_platform()
        .ok_or("unsupported target for embedded mkcert (need linux/macOS/windows amd64/arm64)")?;

    #[cfg(windows)]
    let dest = out_dir.join("mkcert.exe");
    #[cfg(not(windows))]
    let dest = out_dir.join("mkcert");

    if dest.is_file() {
        return Ok(());
    }

    let url = format!("https://dl.filippo.io/mkcert/{MKCERT_VERSION}?for={os}/{arch}");

    let vendor = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
        .join("vendor/mkcert")
        .join(MKCERT_VERSION)
        .join(format!("{os}-{arch}"));
    #[cfg(windows)]
    let vendor_bin = vendor.join("mkcert.exe");
    #[cfg(not(windows))]
    let vendor_bin = vendor.join("mkcert");

    if vendor_bin.is_file() {
        fs::copy(&vendor_bin, &dest)?;
    } else {
        let status = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&dest)
            .arg(&url)
            .status()?;
        if !status.success() {
            return Err(format!("curl failed downloading mkcert from {url}").into());
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))?;
    }

    Ok(())
}
