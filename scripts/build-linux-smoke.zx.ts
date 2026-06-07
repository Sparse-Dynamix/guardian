import { requirePlatform } from "./lib/guard.ts";
import { cargoBuildRelease } from "./lib/cargo.ts";
import { cdRepo, releaseGuardianBin } from "./lib/repo.ts";
import { stageFridaRuntime } from "./lib/stage-frida.ts";

requirePlatform("linux");
cdRepo();
console.log(`Building guardian in ${process.cwd()}`);
cargoBuildRelease();
stageFridaRuntime("linux");
console.log(`Linux smoke artifact: ${releaseGuardianBin()}`);
