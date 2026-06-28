import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "./repo.ts";

// Match llvm-cov filename paths on Unix (bin/foo.rs) and Windows (bin\foo.rs).
export const IGNORED_COVERAGE =
  String.raw`target/patch|[\\/]bin[\\/](ws_smoke|http_smoke|exit_code|sleep_smoke)\.rs|build\.rs|[\\/]install\.rs`;

export function cleanCoverageArtifacts(): void {
  const target = path.join(REPO_ROOT, "target");
  fs.rmSync(path.join(target, "llvm-cov-target"), {
    recursive: true,
    force: true,
  });

  if (!fs.existsSync(target)) {
    return;
  }

  for (const entry of fs.readdirSync(target)) {
    if (entry.startsWith("guardian-") && entry.endsWith(".profraw")) {
      fs.rmSync(path.join(target, entry), { force: true });
    }
  }
}
