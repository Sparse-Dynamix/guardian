import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { requirePlatform } from "./lib/guard.ts";
import { applyJdkEnv, ensurePortableJdk } from "./lib/jdk.ts";
import { applyCratePatches, runCargo } from "./lib/cargo.ts";
import { cdRepo } from "./lib/repo.ts";

requirePlatform("win");
cdRepo();
applyCratePatches();

const llvmCov = path.join(os.homedir(), ".cargo", "bin", "cargo-llvm-cov.exe");
if (!fs.existsSync(llvmCov)) {
  throw new Error(
    "cargo-llvm-cov not found. Install: cargo install cargo-llvm-cov; rustup component add llvm-tools-preview",
  );
}

const javaHome = await ensurePortableJdk("win");
applyJdkEnv(javaHome);

const IGNORED_COVERAGE =
  "target/patch|src/bin/ws_smoke.rs|build.rs|src/install.rs";

runCargo(["llvm-cov", "clean"]);
runCargo([
  "llvm-cov",
  "test",
  "--features",
  "ws-smoke",
  "--",
  "--test-threads=1",
]);
runCargo([
  "llvm-cov",
  "report",
  "--summary-only",
  "--ignore-filename-regex",
  IGNORED_COVERAGE,
  "--fail-under-lines",
  "90",
]);
