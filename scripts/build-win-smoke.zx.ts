import fs from "node:fs";
import { requirePlatform } from "./lib/guard.ts";
import { cargoBuildRelease } from "./lib/cargo.ts";
import { cdRepo, releaseGuardianBin } from "./lib/repo.ts";
import { stageFridaRuntime } from "./lib/stage-frida.ts";

requirePlatform("win");
cdRepo();
console.log(`Building guardian in ${process.cwd()}`);
cargoBuildRelease();

const out = releaseGuardianBin();
if (!fs.existsSync(out)) {
  throw new Error(`missing ${out}`);
}

stageFridaRuntime("win");
console.log(`Windows smoke artifact: ${out}`);
