import { requirePlatform } from "./lib/guard.ts";
import { cargoBuildRelease } from "./lib/cargo.ts";
import { cdRepo, releaseGuardianBin } from "./lib/repo.ts";

requirePlatform("linux");
cdRepo();
console.log(`Building guardian in ${process.cwd()}`);
cargoBuildRelease();
console.log(`Linux smoke artifact: ${releaseGuardianBin()}`);
