use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cargo_metadata::{CargoOpt, DependencyKind, Metadata, MetadataCommand, PackageId};

const MKCERT_VERSION: &str = "v1.4.4";
const NOTICE_FILE: &str = "NOTICE.txt";
const BEGIN_MARKER: &str = "===== BEGIN AUTO-GENERATED: rust-dependency-licenses =====";
const END_MARKER: &str = "===== END AUTO-GENERATED: rust-dependency-licenses =====";

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

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed={NOTICE_FILE}");
    println!("cargo:rerun-if-changed=LICENSE");
    println!("cargo:rerun-if-changed=SECURITY.md");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");

    if let Err(e) = update_notice_dependency_licenses(&manifest_dir) {
        panic!("failed to update {NOTICE_FILE} dependency licenses: {e}");
    }

    if let Err(e) = fetch_mkcert() {
        panic!("failed to fetch mkcert for embedding: {e}");
    }
}

fn update_notice_dependency_licenses(
    manifest_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let notice_path = manifest_dir.join(NOTICE_FILE);
    let inventory = generate_dependency_license_inventory(manifest_dir)?;
    let notice = fs::read_to_string(&notice_path)?;
    let updated = splice_notice_section(&notice, &inventory)?;
    if updated != notice {
        fs::write(&notice_path, updated)?;
    }
    Ok(())
}

fn splice_notice_section(
    notice: &str,
    inventory: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let begin = notice
        .find(BEGIN_MARKER)
        .ok_or("BEGIN marker not found in NOTICE.txt")?;
    let end = notice
        .find(END_MARKER)
        .ok_or("END marker not found in NOTICE.txt")?;
    if end < begin {
        return Err("END marker appears before BEGIN marker in NOTICE.txt".into());
    }

    let mut out = String::with_capacity(notice.len() + inventory.len());
    out.push_str(&notice[..begin + BEGIN_MARKER.len()]);
    out.push('\n');
    out.push_str(inventory);
    if !inventory.is_empty() && !inventory.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&notice[end..]);
    Ok(out)
}

fn generate_dependency_license_inventory(
    manifest_dir: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(manifest_dir.join("Cargo.toml"))
        .features(CargoOpt::AllFeatures)
        .exec()?;

    let by_license = production_dependencies_by_license(&metadata);
    let mut lines = Vec::new();
    for (license, names) in by_license {
        let count = names.len();
        lines.push(format!("{license} ({count}): {}", names.join(", ")));
    }
    Ok(lines.join("\n"))
}

fn production_dependencies_by_license(metadata: &Metadata) -> BTreeMap<String, Vec<String>> {
    let packages: HashMap<&PackageId, &cargo_metadata::Package> =
        metadata.packages.iter().map(|p| (&p.id, p)).collect();

    let resolve = metadata
        .resolve
        .as_ref()
        .expect("cargo metadata resolve graph");
    let nodes: HashMap<&PackageId, &cargo_metadata::Node> =
        resolve.nodes.iter().map(|n| (&n.id, n)).collect();

    let root_id = resolve.root.as_ref().expect("resolve root package id");
    let mut queue = VecDeque::new();
    let mut seen = HashSet::new();
    queue.push_back(root_id.clone());
    seen.insert(root_id.clone());

    while let Some(id) = queue.pop_front() {
        let Some(node) = nodes.get(&id) else {
            continue;
        };
        for dep in &node.deps {
            let is_production = dep.dep_kinds.is_empty()
                || dep
                    .dep_kinds
                    .iter()
                    .any(|k| k.kind == DependencyKind::Normal);
            if !is_production {
                continue;
            }
            if seen.insert(dep.pkg.clone()) {
                queue.push_back(dep.pkg.clone());
            }
        }
    }

    let mut by_license: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in seen {
        let Some(pkg) = packages.get(&id) else {
            continue;
        };
        let license = pkg
            .license
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("UNKNOWN")
            .to_string();
        by_license
            .entry(license)
            .or_default()
            .push(pkg.name.clone());
    }

    for names in by_license.values_mut() {
        names.sort();
        names.dedup();
    }
    by_license
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
