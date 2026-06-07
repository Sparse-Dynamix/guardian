import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { smokeCases } from "./cases.ts";
import type { SmokeCase } from "./cases.ts";
import { curlResolveArgs } from "./dns.ts";
import {
  assertExit,
  assertStderrJsonlType,
  assertStdoutNonempty,
} from "./assert.ts";
import { assertGuardianBuilt, platformConfig } from "./platform.ts";
import { cdRepo, REPO_ROOT } from "../lib/repo.ts";
import { hostPlatform } from "../lib/guard.ts";
import { resolveExecutable } from "../lib/resolve-exec.ts";

const DEFAULT_SMOKE_URL = "http://httpbin.org/get";

function smokeUrl(): string {
  return process.env.SMOKE_URL ?? DEFAULT_SMOKE_URL;
}

function urlHost(url: string): string {
  return url.replace(/^https?:\/\//, "").split("/")[0] ?? "httpbin.org";
}

function makeCaDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "guardian-smoke-ca-"));
}

interface RunResult {
  exitCode: number;
  stdoutFile: string;
  stderrFile: string;
}

function runGuardian(guardianArgs: string[]): RunResult {
  const config = platformConfig();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-smoke-run-"));
  const outPath = path.join(dir, "stdout");
  const stderrFile = path.join(dir, "stderr");

  const result = spawnSync(config.guardianBin, guardianArgs, {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  fs.writeFileSync(outPath, result.stdout ?? "");
  fs.writeFileSync(stderrFile, result.stderr ?? "");

  return {
    exitCode: result.status ?? 1,
    stdoutFile: outPath,
    stderrFile,
  };
}

function runDirect(
  silent: boolean,
  url: string,
  resolveArgs: string[],
): RunResult {
  const config = platformConfig();
  const caDir = makeCaDir();
  const guardianArgs: string[] = [];
  if (silent) guardianArgs.push("--silent");
  guardianArgs.push(
    "--ca-dir",
    caDir,
    "--",
    config.curl,
    "-sSf",
    ...resolveArgs,
    url,
  );
  return runGuardian(guardianArgs);
}

function runChild(
  silent: boolean,
  url: string,
  resolveArgs: string[],
): RunResult {
  const config = platformConfig();
  const caDir = makeCaDir();
  const guardianArgs: string[] = [];
  if (silent) guardianArgs.push("--silent");
  guardianArgs.push("--ca-dir", caDir, "--");

  if (config.childWrapper) {
    guardianArgs.push(
      config.childWrapper,
      config.curl,
      "-sSf",
      ...resolveArgs,
      url,
    );
  } else if (hostPlatform() === "win") {
    const cmd = process.env.COMSPEC ?? resolveExecutable("cmd.exe");
    guardianArgs.push(cmd, "/c", config.curl, "-sSf", ...resolveArgs, url);
  } else if (config.childShell) {
    const resolve = resolveArgs.join(" ");
    const inner = `${config.curl} -sSf ${resolve} '${url}'`.trim();
    guardianArgs.push(...config.childShell, inner);
  } else {
    throw new Error("platform config missing child spawn wrapper");
  }

  return runGuardian(guardianArgs);
}

function runCase(c: SmokeCase, url: string, resolveArgs: string[]): void {
  console.log(`==> smoke case: ${c.name}`);
  const result =
    c.command === "direct"
      ? runDirect(c.silent, url, resolveArgs)
      : runChild(c.silent, url, resolveArgs);

  assertExit(c.expectExit, result.exitCode);
  if (c.expectStdoutNonempty) {
    assertStdoutNonempty(result.stdoutFile);
  }
  assertStderrJsonlType(result.stderrFile, c.expectJsonlType);
  fs.rmSync(path.dirname(result.stdoutFile), { recursive: true, force: true });
  console.log("    ok");
}

export async function runSmokeCases(): Promise<void> {
  cdRepo();
  const config = platformConfig();
  assertGuardianBuilt(config);

  const url = smokeUrl();
  const host = urlHost(url);
  const resolveArgs = curlResolveArgs(url, host);

  for (const c of smokeCases) {
    runCase(c, url, resolveArgs);
  }
  console.log("All smoke cases passed.");
}
