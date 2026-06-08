import path from "node:path";
import { hostPlatform } from "./lib/guard.ts";
import { runZxScript } from "./lib/run-zx.ts";
import { SCRIPTS_DIR } from "./lib/repo.ts";
import { runSmokeCases } from "./smoke/run-cases.ts";
import { runTpfSmokeCases } from "./smoke/run-tpf-cases.ts";
import { startTpfMockServer } from "./smoke/tpf-mock-server.ts";

const buildScript = path.join(
  SCRIPTS_DIR,
  `build-${hostPlatform()}-smoke.zx.ts`,
);

await runZxScript(buildScript);

const tpf = await startTpfMockServer();
try {
  await runSmokeCases();
  await runTpfSmokeCases(tpf);
} finally {
  await tpf.close();
}
