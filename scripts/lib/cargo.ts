import { spawnSync } from "node:child_process";
import path from "node:path";
import { cdRepo, REPO_ROOT } from "./repo.ts";

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
  const result = spawnSync(
    cargo,
    ["run", "--quiet", "--manifest-path", PATCH_PROXYAPI_MANIFEST],
    {
      stdio: "inherit",
      env: process.env,
      cwd: REPO_ROOT,
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `patch-proxyapi failed (exit ${result.status ?? 1})`,
    );
  }
}

export function runCargo(args: string[]): void {
  applyCratePatches();
  cdRepo();
  const cargo = cargoExecutable();
  const result = spawnSync(cargo, args, {
    stdio: "inherit",
    env: process.env,
    cwd: REPO_ROOT,
  });
  if (result.status !== 0) {
    throw new Error(
      `cargo ${args.join(" ")} failed (exit ${result.status ?? 1})`,
    );
  }
}

export function cargoBuildRelease(): void {
  runCargo(["build", "--release"]);
}
