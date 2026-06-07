use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use git2::{ApplyLocation, ApplyOptions, Diff, Repository};
use walkdir::WalkDir;

const PROXYAPI_VERSION: &str = "0.4.5";
const CRATE_DIR: &str = "target/patch/proxyapi-0.4.5";
const PATCH_FILE: &str = "patches/proxyapi+0.4.5.patch";
const STAMP_FILE: &str = "target/proxyapi-patch.stamp";

pub fn apply_if_needed(manifest_dir: &Path) -> Result<()> {
    apply_if_needed_inner(manifest_dir, false)
}

#[allow(dead_code)]
pub fn apply_if_needed_build(manifest_dir: &Path) -> Result<()> {
    apply_if_needed_inner(manifest_dir, true)
}

fn apply_if_needed_inner(manifest_dir: &Path, emit_cargo_directives: bool) -> Result<()> {
    let crate_dir = manifest_dir.join(CRATE_DIR);
    let patch_path = manifest_dir.join(PATCH_FILE);
    let stamp_path = manifest_dir.join(STAMP_FILE);

    if emit_cargo_directives {
        println!("cargo:rerun-if-changed={PATCH_FILE}");
        println!("cargo:rerun-if-changed={CRATE_DIR}/Cargo.toml");
    }

    if !patch_path.is_file() {
        anyhow::bail!("missing patch file: {}", patch_path.display());
    }

    if !crate_dir.join("Cargo.toml").is_file() {
        restore_pristine(&crate_dir)?;
        apply_git_patch(&crate_dir, &patch_path)?;
        write_stamp(&stamp_path, &patch_path)?;
        return Ok(());
    }

    if patch_is_stale(&stamp_path, &patch_path)? {
        restore_pristine(&crate_dir)?;
        apply_git_patch(&crate_dir, &patch_path)?;
        write_stamp(&stamp_path, &patch_path)?;
    }

    Ok(())
}

fn write_stamp(stamp: &Path, patch: &Path) -> Result<()> {
    if let Some(parent) = stamp.parent() {
        fs::create_dir_all(parent)?;
    }
    let mtime = fs::metadata(patch)?.modified()?;
    let encoded = mtime
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    fs::write(stamp, encoded.to_string())?;
    Ok(())
}

fn patch_is_stale(stamp: &Path, patch: &Path) -> Result<bool> {
    let patch_mtime = fs::metadata(patch)
        .with_context(|| format!("stat {}", patch.display()))?
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let stamp_mtime = match fs::read_to_string(stamp) {
        Ok(value) => value.trim().parse().unwrap_or(0),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.into()),
    };
    Ok(patch_mtime > stamp_mtime)
}

fn restore_pristine(dest: &Path) -> Result<()> {
    if dest.exists() {
        fs::remove_dir_all(dest).with_context(|| format!("remove {}", dest.display()))?;
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    if let Some(src) = find_registry_source()? {
        copy_dir_all(&src, dest)?;
        return Ok(());
    }

    download_crate(dest)
}

fn find_registry_source() -> Result<Option<PathBuf>> {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")));
    let Some(cargo_home) = cargo_home else {
        return Ok(None);
    };

    let registry = cargo_home.join("registry").join("src");
    if !registry.is_dir() {
        return Ok(None);
    }

    for entry in fs::read_dir(&registry).with_context(|| registry.display().to_string())? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let candidate = entry.path().join(format!("proxyapi-{PROXYAPI_VERSION}"));
        if candidate.join("Cargo.toml").is_file() {
            return Ok(Some(candidate));
        }
    }

    Ok(None)
}

fn download_crate(dest: &Path) -> Result<()> {
    let url = format!("https://crates.io/api/v1/crates/proxyapi/{PROXYAPI_VERSION}/download");
    let parent = dest
        .parent()
        .context("patch directory has no parent path")?;

    let response = ureq::get(&url)
        .call()
        .with_context(|| format!("download proxyapi {PROXYAPI_VERSION} from crates.io"))?;
    let body = response
        .into_body()
        .read_to_vec()
        .context("read proxyapi crate tarball")?;

    let decoder = flate2::read::GzDecoder::new(body.as_slice());
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(parent)
        .context("extract proxyapi crate tarball")?;

    let extracted = parent.join(format!("proxyapi-{PROXYAPI_VERSION}"));
    if extracted != dest {
        fs::rename(&extracted, dest).with_context(|| {
            format!(
                "move extracted crate from {} to {}",
                extracted.display(),
                dest.display()
            )
        })?;
    }

    Ok(())
}

fn copy_dir_all(src: &Path, dest: &Path) -> Result<()> {
    for entry in WalkDir::new(src) {
        let entry = entry.with_context(|| format!("walk {}", src.display()))?;
        let rel = entry
            .path()
            .strip_prefix(src)
            .context("strip patch source prefix")?;
        let target = dest.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target).with_context(|| {
                format!(
                    "copy {} to {}",
                    entry.path().display(),
                    target.display()
                )
            })?;
        }
    }
    Ok(())
}

fn apply_git_patch(crate_dir: &Path, patch_path: &Path) -> Result<()> {
    let patch_text = fs::read(patch_path)
        .with_context(|| format!("read {}", patch_path.display()))?;
    let diff = Diff::from_buffer(&patch_text)
        .with_context(|| format!("parse {}", patch_path.display()))?;

    let repo = Repository::init(crate_dir)
        .with_context(|| format!("init git repo in {}", crate_dir.display()))?;
    let mut opts = ApplyOptions::new();
    repo.apply(&diff, ApplyLocation::WorkDir, Some(&mut opts))
        .with_context(|| format!("apply {}", patch_path.display()))?;
    fs::remove_dir_all(crate_dir.join(".git")).ok();

    Ok(())
}
