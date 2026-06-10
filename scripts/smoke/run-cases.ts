import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn as spawnProcess } from "node:child_process";
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
import { SMOKE_CASE_TIMEOUT_MS, withSmokeTimeout } from "./timeout.ts";

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
    timeout: SMOKE_CASE_TIMEOUT_MS,
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
  const args = ["-sSf", "--connect-timeout", "5", "--max-time", "20"];
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

async function freeLocalPort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") {
        server.close();
        reject(new Error("failed to allocate local port"));
        return;
      }
      const { port } = addr;
      server.close(() => resolve(port));
    });
  });
}

async function waitForListener(port: number): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const ok = await new Promise<boolean>((resolve) => {
      const socket = net.connect({ host: "127.0.0.1", port });
      const done = (value: boolean) => {
        socket.destroy();
        resolve(value);
      };
      socket.setTimeout(100, () => done(false));
      socket.once("connect", () => done(true));
      socket.once("error", () => done(false));
    });
    if (ok) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`guardian proxy listener did not start on port ${port}`);
}

async function waitForExit(
  child: ReturnType<typeof spawnProcess>,
  timeoutMs: number,
): Promise<number> {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`guardian did not exit within ${timeoutMs}ms`));
    }, timeoutMs);
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (code !== null) {
        resolve(code);
        return;
      }
      resolve(signal === "SIGINT" ? 130 : 1);
    });
  });
}

async function assertNoScriptProcess(scriptPath: string): Promise<void> {
  if (hostPlatform() === "win") {
    return;
  }
  const result = await $({
    cwd: REPO_ROOT,
    quiet: true,
    nothrow: true,
  })`ps -eo pid=,args=`;
  const survivors = (result.stdout ?? "")
    .split("\n")
    .filter((line) => line.includes(scriptPath));
  if (survivors.length > 0) {
    throw new Error(`sleep child survived interrupt:\n${survivors.join("\n")}`);
  }
}

async function runInterrupt(servers: TestServers): Promise<RunResult> {
  const config = platformConfig();
  const dir = fs.mkdtempSync(
    path.join(os.tmpdir(), "guardian-smoke-interrupt-"),
  );
  const outPath = path.join(dir, "stdout");
  const stderrFile = path.join(dir, "stderr");
  const caDir = makeCaDir();
  const port = await freeLocalPort();

  let childProgram: string;
  let childArgs: string[];
  let scriptPath: string | undefined;
  if (hostPlatform() === "win") {
    childProgram = resolveExecutable("cmd.exe");
    childArgs = ["/c", "ping -n 60 127.0.0.1 >NUL"];
  } else {
    scriptPath = path.join(dir, `guardian-smoke-sleep-${process.pid}.sh`);
    fs.writeFileSync(scriptPath, "#!/bin/sh\nsleep 60 &\nwait\n");
    fs.chmodSync(scriptPath, 0o755);
    childProgram = resolveExecutable("sh");
    childArgs = [scriptPath];
  }

  const child = spawnProcess(
    config.guardianBin,
    [
      "--ca-dir",
      caDir,
      "--tpf",
      servers.tpf.passUrl,
      "--port",
      String(port),
      "--",
      childProgram,
      ...childArgs,
    ],
    {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout?.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
  child.stderr?.on("data", (chunk) => stderr.push(Buffer.from(chunk)));

  let exitCode: number;
  try {
    await waitForListener(port);
    await new Promise((resolve) => setTimeout(resolve, 500));
    child.kill("SIGINT");
    exitCode = await waitForExit(child, 15_000);
    await new Promise((resolve) => setTimeout(resolve, 200));
    if (scriptPath) {
      await assertNoScriptProcess(scriptPath);
    }
  } catch (err) {
    child.kill("SIGKILL");
    throw err;
  }

  fs.writeFileSync(outPath, Buffer.concat(stdout));
  fs.writeFileSync(stderrFile, Buffer.concat(stderr));
  return { exitCode, stdoutFile: outPath, stderrFile };
}

async function runCase(
  c: SmokeCase,
  url: string,
  servers: TestServers,
): Promise<void> {
  console.log(`==> smoke case: ${c.name}`);
  let lastError: unknown;
  for (let attempt = 1; attempt <= SMOKE_RETRIES; attempt++) {
    const result = await withSmokeTimeout(
      `smoke case ${c.name}`,
      c.command === "direct"
        ? runDirect(url)
        : c.command === "child"
          ? runChild(url)
          : runInterrupt(servers),
    );

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
    await runCase(c, url, servers);
  }
  console.log("All smoke cases passed.");
}
