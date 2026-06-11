import { $ } from "zx";
import { requirePlatform } from "./lib/guard.ts";
import { applyJdkEnv, ensurePortableJdk } from "./lib/jdk.ts";
import { applyCratePatches } from "./lib/cargo.ts";
import { cdRepo } from "./lib/repo.ts";
import { cleanCoverageArtifacts, IGNORED_COVERAGE } from "./lib/coverage.ts";

requirePlatform("linux");
cdRepo();
applyCratePatches();

await $`command -v cargo-llvm-cov`.quiet().catch(() => {
  throw new Error(
    "cargo-llvm-cov not found. Install: cargo install cargo-llvm-cov; rustup component add llvm-tools-preview",
  );
});

const javaHome = await ensurePortableJdk("linux");
applyJdkEnv(javaHome);

await $`cargo llvm-cov clean`;
cleanCoverageArtifacts();
await $`cargo llvm-cov test --features ws-smoke --ignore-filename-regex ${IGNORED_COVERAGE} --fail-under-lines 90 -- --test-threads=1`;
await $`cargo llvm-cov report --summary-only --ignore-filename-regex ${IGNORED_COVERAGE} --fail-under-lines 90`;
