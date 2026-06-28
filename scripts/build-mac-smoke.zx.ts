import fs from "node:fs";
import path from "node:path";
import { requirePlatform } from "./lib/guard.ts";
import { cargoBuildRelease } from "./lib/cargo.ts";
import {
  prepareMacSmokePath,
  signGuardianBin,
  stageSignedCurl,
  stageSignedEnv,
  stageSignedPrintenv,
} from "./lib/mac-codesign.ts";
import { cdRepo, releaseGuardianBin, REPO_ROOT } from "./lib/repo.ts";

requirePlatform("mac");
cdRepo();
console.log(`Building guardian in ${process.cwd()}`);
cargoBuildRelease();

const out = releaseGuardianBin();
if (!fs.existsSync(out)) {
  throw new Error(`missing ${out}`);
}

const releaseDir = path.join(REPO_ROOT, "target", "release");
console.log("==> ad-hoc signing guardian (get-task-allow) for Frida injection");
await signGuardianBin(out);
console.log(
  "==> staging ad-hoc signed curl/env/printenv for smoke child targets",
);
await stageSignedCurl(releaseDir);
await stageSignedEnv(releaseDir);
await stageSignedPrintenv(releaseDir);
const httpSmoke = path.join(releaseDir, "guardian-http-smoke");
if (fs.existsSync(httpSmoke)) {
  await signGuardianBin(httpSmoke);
}
await prepareMacSmokePath(releaseDir);
console.log(`macOS smoke artifact: ${out}`);
