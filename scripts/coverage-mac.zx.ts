import path from "node:path";
import { $ } from "zx";
import { requirePlatform } from "./lib/guard.ts";
import { applyJdkEnv, ensurePortableJdk } from "./lib/jdk.ts";
import { cdRepo, REPO_ROOT, SCRIPTS_DIR } from "./lib/repo.ts";

requirePlatform("mac");
cdRepo();

await $`command -v cargo-llvm-cov`.quiet().catch(() => {
  throw new Error(
    "cargo-llvm-cov not found. Install: cargo install cargo-llvm-cov; rustup component add llvm-tools-preview",
  );
});

const javaHome = await ensurePortableJdk("mac");
applyJdkEnv(javaHome);

const wrapper = path.join(SCRIPTS_DIR, "rustc-codesign-wrapper.zx.ts");

await $`cargo llvm-cov clean`;

const showEnv = await $`cargo llvm-cov show-env --export-prefix`.quiet();
for (const line of showEnv.stdout.split("\n")) {
  const m = line.match(/^export (\w+)=(.*)$/);
  if (!m) continue;
  const value = m[2].replace(/^'(.*)'$/, "$1");
  process.env[m[1]] = value;
}

process.env.CARGO_LLVM_COV_RUSTC_DELEGATE = process.env.RUSTC_WRAPPER ?? "";
process.env.RUSTC_WRAPPER = wrapper;
process.env.LLVM_PROFILE_FILE = path.join(
  REPO_ROOT,
  "target",
  "guardian-%p.profraw",
);

const { prepareMacSmokePath } = await import("./lib/mac-codesign.ts");
process.env.PATH = await prepareMacSmokePath(
  path.join(REPO_ROOT, "target", "debug"),
);

await $`cargo llvm-cov test --no-rustc-wrapper --features ws-smoke --fail-under-lines 90 -- --test-threads=1`;
