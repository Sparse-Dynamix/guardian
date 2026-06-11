import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "./repo.ts";

export const IGNORED_COVERAGE =
  "target/patch|src/bin/ws_smoke.rs|src/bin/http_smoke.rs|src/bin/exit_code.rs|build.rs|src/install.rs";

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
