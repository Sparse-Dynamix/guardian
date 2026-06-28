import path from "node:path";
import { $ } from "zx";
import { hostPlatform } from "./lib/guard.ts";
import { runZxScript } from "./lib/run-zx.ts";
import { REPO_ROOT, SCRIPTS_DIR } from "./lib/repo.ts";
import { runSmokeCases } from "./smoke/run-cases.ts";
import { runTpfSmokeCases } from "./smoke/run-tpf-cases.ts";
import { startTestServers } from "./test-servers.ts";

const buildScript = path.join(
  SCRIPTS_DIR,
  `build-${hostPlatform()}-smoke.zx.ts`,
);

await runZxScript(buildScript);

await $`node --import tsx --test scripts/connect-bypass.test.ts`;
await $`node --import tsx --test scripts/connect-handshake.test.ts`;

if (hostPlatform() === "mac") {
  const guardian = path.join(REPO_ROOT, "target", "release", "guardian");
  await $({ nothrow: true })`pkill -f ${guardian}`;
}

const servers = await startTestServers();
try {
  await runSmokeCases(servers);
  await runTpfSmokeCases(servers);
} finally {
  await servers.close();
}
