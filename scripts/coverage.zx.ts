import path from "node:path";
import { hostPlatform } from "./lib/guard.ts";
import { runZxScript } from "./lib/run-zx.ts";
import { SCRIPTS_DIR } from "./lib/repo.ts";

const coverageScript = path.join(
  SCRIPTS_DIR,
  `coverage-${hostPlatform()}.zx.ts`,
);

await runZxScript(coverageScript);
