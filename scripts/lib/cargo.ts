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

export function runCargo(args: string[]): void {
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
