use std::path::PathBuf;

#[path = "../../../build/apply_proxyapi_patch.rs"]
mod apply_proxyapi_patch;

fn main() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve guardian repository root");

    apply_proxyapi_patch::apply_if_needed(&repo_root).expect("apply proxyapi patch");
}
