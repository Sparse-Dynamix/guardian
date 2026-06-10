import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { $, usePowerShell } from "zx";
import { smokeCases } from "./cases.ts";
import type { SmokeCase } from "./cases.ts";
import type { TestServers } from "../test-servers.ts";
import {
  assertExit,
  assertNoJsonlOnStderr,
  assertStdoutNonempty,
} from "./assert.ts";
import { assertGuardianBuilt, platformConfig } from "./platform.ts";
import { cdRepo, REPO_ROOT } from "../lib/repo.ts";
import { hostPlatform } from "../lib/guard.ts";
import { resolveExecutable } from "../lib/resolve-exec.ts";

if (process.platform === "win32") {
  usePowerShell();
}

const SMOKE_RETRIES = 3;

function makeCaDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "guardian-smoke-ca-"));
}

interface RunResult {
  exitCode: number;
  stdoutFile: string;
  stderrFile: string;
}

async function runGuardian(guardianArgs: string[]): Promise<RunResult> {
  const config = platformConfig();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-smoke-run-"));
  const outPath = path.join(dir, "stdout");
  const stderrFile = path.join(dir, "stderr");

  const opts = {
    cwd: REPO_ROOT,
    quiet: true,
    nothrow: true,
    stdio: ["ignore", "pipe", "pipe"] as const,
  };
  const result =
    hostPlatform() === "win"
      ? await $(opts)`& ${config.guardianBin} ${guardianArgs}`
      : await $(opts)`${config.guardianBin} ${guardianArgs}`;
  fs.writeFileSync(outPath, result.stdout ?? "");
  fs.writeFileSync(stderrFile, result.stderr ?? "");

  return {
    exitCode: result.exitCode ?? 1,
    stdoutFile: outPath,
    stderrFile,
  };
}

function curlArgs(url: string): string[] {
  const args = ["-sSf"];
  if (hostPlatform() === "mac") {
    args.push("--ipv4");
  }
  args.push(url);
  return args;
}

async function runDirect(url: string): Promise<RunResult> {
  const config = platformConfig();
  const caDir = makeCaDir();
  const guardianArgs: string[] = [
    "--ca-dir",
    caDir,
    "--",
    config.curl,
    ...curlArgs(url),
  ];
  return runGuardian(guardianArgs);
}

async function runChild(url: string): Promise<RunResult> {
  const config = platformConfig();
  const caDir = makeCaDir();
  const guardianArgs: string[] = ["--ca-dir", caDir, "--"];

  if (config.childWrapper) {
    guardianArgs.push(config.childWrapper, config.curl, ...curlArgs(url));
  } else if (hostPlatform() === "win") {
    const cmd = process.env.COMSPEC ?? resolveExecutable("cmd.exe");
    guardianArgs.push(cmd, "/c", config.curl, ...curlArgs(url));
  } else if (config.childShell) {
    const inner = `${config.curl} ${curlArgs(url).join(" ")}`.trim();
    guardianArgs.push(...config.childShell, inner);
  } else {
    throw new Error("platform config missing child spawn wrapper");
  }

  return runGuardian(guardianArgs);
}

async function runCase(c: SmokeCase, url: string): Promise<void> {
  console.log(`==> smoke case: ${c.name}`);
  let lastError: unknown;
  for (let attempt = 1; attempt <= SMOKE_RETRIES; attempt++) {
    const result =
      c.command === "direct" ? await runDirect(url) : await runChild(url);

    try {
      assertExit(c.expectExit, result.exitCode);
      if (c.expectStdoutNonempty) {
        assertStdoutNonempty(result.stdoutFile);
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

export async function runSmokeCases(servers: TestServers): Promise<void> {
  cdRepo();
  const config = platformConfig();
  assertGuardianBuilt(config);

  const url = process.env.SMOKE_URL ?? servers.http.getUrl;

  for (const c of smokeCases) {
    await runCase(c, url);
  }
  console.log("All smoke cases passed.");
}
