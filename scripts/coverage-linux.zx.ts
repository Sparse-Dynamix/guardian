import { $ } from "zx";
import { requirePlatform } from "./lib/guard.ts";
import { applyJdkEnv, ensurePortableJdk } from "./lib/jdk.ts";
import { applyCratePatches } from "./lib/cargo.ts";
import { cdRepo } from "./lib/repo.ts";

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
await $`cargo llvm-cov test --features ws-smoke --fail-under-lines 90 -- --test-threads=1`;
