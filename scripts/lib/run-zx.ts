import path from "node:path";
import { $, usePowerShell } from "zx";
import { cdRepo, REPO_ROOT } from "./repo.ts";

if (process.platform === "win32") {
  usePowerShell();
  $.bail = true;
}

export function zxCliPath(): string {
  return path.join(REPO_ROOT, "node_modules", "zx", "build", "cli.js");
}

export async function runZxScript(scriptPath: string): Promise<void> {
  cdRepo();
  const result = await $({
    stdio: "inherit",
    env: process.env,
    cwd: REPO_ROOT,
    nothrow: true,
  })`node --import tsx ${zxCliPath()} ${scriptPath}`;
  if (result.exitCode !== 0) {
    throw new Error(
      `zx script failed: ${scriptPath} (exit ${result.exitCode ?? 1})`,
    );
  }
}
