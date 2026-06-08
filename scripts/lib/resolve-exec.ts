import { $, usePowerShell } from "zx";
import { hostPlatform } from "./guard.ts";

if (process.platform === "win32") {
  usePowerShell();
}

export function resolveExecutable(name: string): string {
  const which = hostPlatform() === "win" ? "where.exe" : "which";
  const result = $.sync({ quiet: true, nothrow: true })`${which} ${name}`;
  if (result.exitCode === 0 && result.stdout) {
    const line = result.stdout.split(/\r?\n/).find((l) => l.trim().length > 0);
    if (line?.trim()) return line.trim();
  }
  return name;
}
