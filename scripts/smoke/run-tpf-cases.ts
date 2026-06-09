import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { $, usePowerShell } from "zx";
import { tpfSmokeCases } from "./tpf-cases.ts";
import type { TpfSmokeCase } from "./tpf-cases.ts";
import {
  assertExit,
  assertNoJsonlOnStderr,
  assertStdoutContains,
  assertStdoutEquals,
  assertStdoutNonempty,
} from "./assert.ts";
import type { TpfMockServer } from "./tpf-mock-server.ts";
import { assertGuardianBuilt, platformConfig } from "./platform.ts";
import { cdRepo, REPO_ROOT } from "../lib/repo.ts";
import { hostPlatform } from "../lib/guard.ts";

if (process.platform === "win32") {
  usePowerShell();
}

const DEFAULT_SMOKE_URL = "http://httpbingo.org/get";
const SMOKE_RETRIES = 3;

function smokeUrl(): string {
  return process.env.SMOKE_URL ?? DEFAULT_SMOKE_URL;
}

function makeCaDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "guardian-smoke-ca-"));
}

function tpfUrl(
  server: TpfMockServer,
  which: TpfSmokeCase["tpf"],
): string | undefined {
  if (which === "pass") return server.passUrl;
  if (which === "reject") return server.rejectUrl;
  return undefined;
}

interface RunResult {
  exitCode: number;
  stdoutFile: string;
  stderrFile: string;
}

function curlArgs(url: string, failOnHttpError: boolean): string[] {
  const config = platformConfig();
  const args = [failOnHttpError ? "-sSf" : "-sS"];
  if (hostPlatform() === "mac") {
    args.push("--ipv4");
  }
  args.push(url);
  return [config.curl, ...args];
}

async function runGuardianProcess(
  guardianArgs: string[],
  stdin?: string,
): Promise<RunResult> {
  const config = platformConfig();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-tpf-run-"));
  const outPath = path.join(dir, "stdout");
  const stderrFile = path.join(dir, "stderr");

  const opts = {
    cwd: REPO_ROOT,
    quiet: true,
    nothrow: true,
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
  server: TpfMockServer,
): Promise<RunResult> {
  const args: string[] = [];
  const url = tpfUrl(server, c.tpf);
  if (url) {
    args.push("--tpf", url);
  }
  if (c.useStdin) {
    return runGuardianProcess(args, "test\n");
  }
  args.push("--payload", "hello");
  return runGuardianProcess(args);
}

async function runMitmCase(
  c: TpfSmokeCase,
  server: TpfMockServer,
  url: string,
): Promise<RunResult> {
  const caDir = makeCaDir();
  const args: string[] = ["--ca-dir", caDir];
  const tpf = tpfUrl(server, c.tpf);
  if (tpf) {
    args.push("--tpf", tpf);
  }
  args.push("--", ...curlArgs(url, c.tpf !== "reject"));
  return runGuardianProcess(args);
}

async function runCase(
  c: TpfSmokeCase,
  server: TpfMockServer,
  url: string,
): Promise<void> {
  console.log(`==> tpf smoke case: ${c.name}`);
  let lastError: unknown;
  for (let attempt = 1; attempt <= SMOKE_RETRIES; attempt++) {
    const result =
      c.mode === "payload"
        ? await runPayloadCase(c, server)
        : await runMitmCase(c, server, url);

    try {
      assertExit(c.expectExit, result.exitCode);
      if (c.expectStdoutNonempty) {
        assertStdoutNonempty(result.stdoutFile);
      }
      if (c.expectStdoutContains) {
        assertStdoutContains(result.stdoutFile, c.expectStdoutContains);
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

export async function runTpfSmokeCases(server: TpfMockServer): Promise<void> {
  cdRepo();
  const config = platformConfig();
  assertGuardianBuilt(config);

  const url = smokeUrl();
  for (const c of tpfSmokeCases) {
    await runCase(c, server, url);
  }
  console.log("All TPF smoke cases passed.");
}
