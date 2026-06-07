import path from "node:path";
import { fileURLToPath } from "node:url";

const LIB_DIR = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(LIB_DIR, "../..");
export const SCRIPTS_DIR = path.resolve(LIB_DIR, "..");

export function cdRepo(): void {
  process.chdir(REPO_ROOT);
}

export function releaseGuardianBin(): string {
  const name = process.platform === "win32" ? "guardian.exe" : "guardian";
  return path.join(REPO_ROOT, "target", "release", name);
}
