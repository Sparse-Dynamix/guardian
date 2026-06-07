import fs from "node:fs";
import path from "node:path";
import { hostPlatform } from "../lib/guard.ts";
import { REPO_ROOT } from "../lib/repo.ts";
import { resolveExecutable } from "../lib/resolve-exec.ts";

export interface PlatformConfig {
  guardianBin: string;
  curl: string;
  childShell?: string[];
  childWrapper?: string;
}

export function platformConfig(): PlatformConfig {
  const release = path.join(REPO_ROOT, "target", "release");
  switch (hostPlatform()) {
    case "linux":
      return {
        guardianBin: path.join(release, "guardian"),
        curl: resolveExecutable("curl"),
        childShell: [resolveExecutable("sh"), "-c"],
      };
    case "mac":
      return {
        guardianBin: path.join(release, "guardian"),
        curl: path.join(release, "guardian-curl"),
        childWrapper: path.join(release, "guardian-env"),
      };
    case "win":
      return {
        guardianBin: path.join(release, "guardian.exe"),
        curl: resolveExecutable("curl.exe"),
      };
  }
}

export function assertGuardianBuilt(config: PlatformConfig): void {
  if (!fs.existsSync(config.guardianBin)) {
    throw new Error(
      `guardian binary not found at ${config.guardianBin} — run build-*-smoke.zx.ts first`,
    );
  }
}
