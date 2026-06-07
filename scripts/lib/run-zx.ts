import { spawnSync } from "node:child_process";
import path from "node:path";
import { cdRepo, REPO_ROOT } from "./repo.ts";

export function zxCliPath(): string {
  return path.join(REPO_ROOT, "node_modules", "zx", "build", "cli.js");
}

export async function runZxScript(scriptPath: string): Promise<void> {
  cdRepo();
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", zxCliPath(), scriptPath],
    { stdio: "inherit", env: process.env, cwd: REPO_ROOT },
  );
  if (result.status !== 0) {
    throw new Error(
      `zx script failed: ${scriptPath} (exit ${result.status ?? 1})`,
    );
  }
}
