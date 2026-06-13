import fs from "node:fs";
import path from "node:path";
import { requirePlatform } from "./lib/guard.ts";
import { applyJdkEnv, ensurePortableJdk } from "./lib/jdk.ts";
import { applyCratePatches, cargoHome, runCargo } from "./lib/cargo.ts";
import { cleanCoverageArtifacts, IGNORED_COVERAGE } from "./lib/coverage.ts";
import { cdRepo } from "./lib/repo.ts";

requirePlatform("win");
cdRepo();
applyCratePatches();

const llvmCov = path.join(cargoHome(), "bin", "cargo-llvm-cov.exe");
if (!fs.existsSync(llvmCov)) {
  throw new Error(
    "cargo-llvm-cov not found. Install: cargo install cargo-llvm-cov; rustup component add llvm-tools-preview",
  );
}

const javaHome = await ensurePortableJdk("win");
applyJdkEnv(javaHome);

runCargo(["llvm-cov", "clean"]);
cleanCoverageArtifacts();
runCargo([
  "llvm-cov",
  "test",
  "--features",
  "ws-smoke",
  "--ignore-filename-regex",
  IGNORED_COVERAGE,
  "--fail-under-lines",
  "90",
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
