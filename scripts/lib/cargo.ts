import path from "node:path";
import { $, usePowerShell } from "zx";
import { cdRepo, REPO_ROOT } from "./repo.ts";

if (process.platform === "win32") {
  usePowerShell();
}

function cargoExecutable(): string {
  if (process.platform === "win32") {
    const home = process.env.USERPROFILE ?? process.env.HOME ?? "";
    return path.join(home, ".cargo", "bin", "cargo.exe");
  }
  return "cargo";
}

const PATCH_PROXYAPI_MANIFEST = path.join(
  REPO_ROOT,
  "tools",
  "patch-proxyapi",
  "Cargo.toml",
);

export function applyCratePatches(): void {
  cdRepo();
  const cargo = cargoExecutable();
  const shell = $.sync({
    stdio: "inherit",
    env: process.env,
    cwd: REPO_ROOT,
    nothrow: true,
  });
  const result =
    process.platform === "win32"
      ? shell`& ${cargo} run --quiet --manifest-path ${PATCH_PROXYAPI_MANIFEST}`
      : shell`${cargo} run --quiet --manifest-path ${PATCH_PROXYAPI_MANIFEST}`;
  if (result.exitCode !== 0) {
    throw new Error(`patch-proxyapi failed (exit ${result.exitCode ?? 1})`);
  }
}

export function runCargo(args: string[]): void {
  applyCratePatches();
  cdRepo();
  const cargo = cargoExecutable();
  const shell = $.sync({
    stdio: "inherit",
    env: process.env,
    cwd: REPO_ROOT,
    nothrow: true,
  });
  const result =
    process.platform === "win32"
      ? shell`& ${cargo} ${args}`
      : shell`${cargo} ${args}`;
  if (result.exitCode !== 0) {
    throw new Error(
      `cargo ${args.join(" ")} failed (exit ${result.exitCode ?? 1})`,
    );
  }
}

export function cargoBuildRelease(): void {
  runCargo(["build", "--release"]);
}
