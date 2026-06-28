import fs from "node:fs";
import { requirePlatform } from "./lib/guard.ts";
import { cargoBuildRelease } from "./lib/cargo.ts";
import { cdRepo, releaseGuardianBin } from "./lib/repo.ts";

requirePlatform("win");
cdRepo();
console.log(`Building guardian in ${process.cwd()}`);
cargoBuildRelease(["ws-smoke"]);

const out = releaseGuardianBin();
if (!fs.existsSync(out)) {
  throw new Error(`missing ${out}`);
}

console.log(`Windows smoke artifact: ${out}`);
