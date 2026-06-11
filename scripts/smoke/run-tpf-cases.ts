import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { $, usePowerShell } from "zx";
import { tpfSmokeCases } from "./tpf-cases.ts";
import type { TpfSmokeCase, TpfSmokeTarget } from "./tpf-cases.ts";
import {
  assertContentType,
  assertExit,
  assertNoJsonlOnStderr,
  assertStdoutContains,
  assertStdoutEquals,
  assertStdoutNotContains,
  assertStdoutNonempty,
} from "./assert.ts";
import type { TestServers } from "../test-servers.ts";
import { assertGuardianBuilt, platformConfig } from "./platform.ts";
import { cdRepo, REPO_ROOT } from "../lib/repo.ts";
import { hostPlatform } from "../lib/guard.ts";
import { resolveExecutable } from "../lib/resolve-exec.ts";
import { SMOKE_CASE_TIMEOUT_MS, withSmokeTimeout } from "./timeout.ts";

if (process.platform === "win32") {
  usePowerShell();
}

const SMOKE_RETRIES = 3;

interface CaseTarget {
  url: string;
  env?: Record<string, string>;
}

function resolveCaseTarget(c: TpfSmokeCase, servers: TestServers): CaseTarget {
  const target: TpfSmokeTarget = c.target ?? "localHttp";
  switch (target) {
    case "localHttp":
      return { url: servers.http.getUrl };
    case "localSse":
      return { url: `${servers.sse.baseUrl}/` };
    case "localImage":
      return { url: servers.http.imagePngUrl };
    case "remoteHttp":
      return {
        url: process.env.SMOKE_URL ?? "http://httpbingo.org/get",
      };
    case "remoteImage":
      return {
        url: process.env.SMOKE_IMAGE_URL ?? "https://httpbingo.org/image/png",
      };
    case "remoteSse":
      return {
        url: process.env.SMOKE_SSE_URL ?? "https://httpbingo.org/sse",
      };
    case "remoteHttp2":
      return {
        url: process.env.SMOKE_HTTPS_URL ?? "https://httpbingo.org/get",
      };
    case "localHttp2":
      return {
        url: servers.http2.getUrl,
        env: {
          GUARDIAN_UPSTREAM_TLS: `default+ca:${servers.originCaPem}`,
        },
      };
    case "localHttp2c":
      return { url: servers.http2c.getUrl };
    default:
      return { url: servers.http.getUrl };
  }
}

function makeCaDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "guardian-smoke-ca-"));
}

function tpfUrl(
  servers: TestServers,
  which: TpfSmokeCase["tpf"],
): string | undefined {
  if (which === "pass") return servers.tpf.passUrl;
  if (which === "reject") return servers.tpf.rejectUrl;
  if (which === "swap") return servers.tpf.swapUrl;
  if (which === "image-swap") return servers.tpf.imageSwapUrl;
  return undefined;
}

interface RunResult {
  exitCode: number;
  stdoutFile: string;
  stderrFile: string;
}

function curlArgs(
  config: ReturnType<typeof platformConfig>,
  url: string,
  caDir: string,
  includeHeaders: boolean,
  failOnHttpError: boolean,
  extra: string[] = [],
  tpfActive = false,
): string[] {
  const args = [
    config.curl,
    failOnHttpError ? "-sSf" : "-sS",
    "--connect-timeout",
    "5",
    "--max-time",
    "20",
    ...extra,
  ];
  if (includeHeaders) {
    args.push("-i");
  }
  if (hostPlatform() === "mac") {
    args.push("--ipv4");
  }
  if (url.startsWith("https://")) {
    if (tpfActive) {
      args.push("--cacert", path.join(caDir, "guardian-ca-bundle.pem"));
    }
    if (hostPlatform() === "win") {
      args.push("--ipv4", "--ssl-no-revoke");
    }
  }
  args.push(url);
  return args;
}

function childArgs(
  config: ReturnType<typeof platformConfig>,
  c: TpfSmokeCase,
  url: string,
  caDir: string,
): string[] {
  if (c.printenvVar) {
    if (hostPlatform() === "win") {
      return [resolveExecutable("cmd.exe"), "/c", `echo %${c.printenvVar}%`];
    }
    const sh = resolveExecutable("sh");
    return [sh, "-c", `echo $${c.printenvVar}`];
  }

  const failOnHttpError = c.tpf !== "reject";
  const tpfActive = c.tpf !== "";
  const curl = curlArgs(
    config,
    url,
    caDir,
    c.curlIncludeHeaders ?? false,
    failOnHttpError,
    c.curlExtra ?? [],
    tpfActive,
  );

  if (hostPlatform() === "win") {
    return [resolveExecutable("cmd.exe"), "/c", curl.join(" ")];
  }
  if (config.childWrapper) {
    return [config.childWrapper, ...curl];
  }
  return curl;
}

async function runGuardianProcess(
  guardianArgs: string[],
  stdin?: string,
  env?: Record<string, string>,
): Promise<RunResult> {
  const config = platformConfig();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-tpf-run-"));
  const outPath = path.join(dir, "stdout");
  const stderrFile = path.join(dir, "stderr");

  const opts = {
    cwd: REPO_ROOT,
    quiet: true,
    nothrow: true,
    timeout: SMOKE_CASE_TIMEOUT_MS,
    env: { ...process.env, ...env },
    ...(stdin !== undefined
      ? { input: stdin }
      : { stdio: ["ignore", "pipe", "pipe"] as const }),
  };
  const result =
    hostPlatform() === "win"
      ? await $(opts)`& ${config.guardianBin} ${guardianArgs}`
      : await $(opts)`${config.guardianBin} ${guardianArgs}`;

  fs.writeFileSync(outPath, result.stdout ?? "");
  fs.writeFileSync(stderrFile, result.stderr ?? "");

  return { exitCode: result.exitCode ?? 1, stdoutFile: outPath, stderrFile };
}

async function runPayloadCase(
  c: TpfSmokeCase,
  servers: TestServers,
): Promise<RunResult> {
  const args: string[] = [];
  const url = tpfUrl(servers, c.tpf);
  if (url) {
    args.push("--tpf", url);
  }
  if (c.tps) {
    args.push("--tps");
  }
  if (c.useStdin) {
    return runGuardianProcess(args, "test\n", c.env);
  }
  args.push("--payload", "hello");
  return runGuardianProcess(args, undefined, c.env);
}

async function runMitmCase(
  c: TpfSmokeCase,
  servers: TestServers,
  url: string,
  extraEnv?: Record<string, string>,
): Promise<RunResult> {
  const config = platformConfig();
  const caDir = makeCaDir();
  const args: string[] = ["--ca-dir", caDir];
  const tpf = tpfUrl(servers, c.tpf);
  if (tpf) {
    args.push("--tpf", tpf);
  }
  if (c.tps) {
    args.push("--tps");
  }
  args.push("--", ...childArgs(config, c, url, caDir));
  return runGuardianProcess(args, undefined, { ...extraEnv, ...c.env });
}

async function runCase(c: TpfSmokeCase, servers: TestServers): Promise<void> {
  console.log(`==> tpf smoke case: ${c.name}`);
  const { url, env } = resolveCaseTarget(c, servers);
  let lastError: unknown;
  for (let attempt = 1; attempt <= SMOKE_RETRIES; attempt++) {
    const result = await withSmokeTimeout(
      `tpf smoke case ${c.name}`,
      c.mode === "payload"
        ? runPayloadCase(c, servers)
        : runMitmCase(c, servers, url, env),
    );

    try {
      assertExit(c.expectExit, result.exitCode);
      if (c.expectStdoutNonempty) {
        assertStdoutNonempty(result.stdoutFile);
      }
      if (c.expectStdoutContains) {
        assertStdoutContains(result.stdoutFile, c.expectStdoutContains);
      }
      if (c.expectStdoutNotContains) {
        assertStdoutNotContains(result.stdoutFile, c.expectStdoutNotContains);
      }
      if (c.expectContentType) {
        assertContentType(result.stdoutFile, c.expectContentType);
      }
      if (c.expectStdoutEquals !== undefined) {
        assertStdoutEquals(result.stdoutFile, c.expectStdoutEquals);
      }
      assertNoJsonlOnStderr(result.stderrFile);
      fs.rmSync(path.dirname(result.stdoutFile), {
        recursive: true,
        force: true,
      });
      console.log("    ok");
      return;
    } catch (err) {
      lastError = err;
      fs.rmSync(path.dirname(result.stdoutFile), {
        recursive: true,
        force: true,
      });
      if (attempt < SMOKE_RETRIES) {
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
  }
  throw lastError;
}

export async function runTpfSmokeCases(servers: TestServers): Promise<void> {
  cdRepo();
  const config = platformConfig();
  assertGuardianBuilt(config);

  for (const c of tpfSmokeCases) {
    await runCase(c, servers);
  }
  console.log("All TPF smoke cases passed.");
}
