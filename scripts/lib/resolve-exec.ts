import { spawnSync } from "node:child_process";
import { hostPlatform } from "./guard.ts";

export function resolveExecutable(name: string): string {
  const which = hostPlatform() === "win" ? "where.exe" : "which";
  const result = spawnSync(which, [name], { encoding: "utf8" });
  if (result.status === 0 && result.stdout) {
    const line = result.stdout.split(/\r?\n/).find((l) => l.trim().length > 0);
    if (line?.trim()) return line.trim();
  }
  return name;
}
