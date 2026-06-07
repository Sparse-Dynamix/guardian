import fs from "node:fs";

export function assertExit(expected: number, actual: number): void {
  if (actual !== expected) {
    throw new Error(`ASSERT exit: expected ${expected}, got ${actual}`);
  }
}

export function assertStdoutNonempty(file: string): void {
  const stat = fs.statSync(file);
  if (stat.size === 0) {
    throw new Error("ASSERT stdout: expected non-empty output");
  }
}

export function assertStderrJsonlType(stderrFile: string, type: string): void {
  const stderr = fs.readFileSync(stderrFile, "utf8");
  if (!type) {
    if (/^\{/m.test(stderr)) {
      throw new Error("ASSERT stderr: expected no JSONL, found JSON lines");
    }
    return;
  }
  const patterns = [`"type":"${type}"`, `"type": "${type}"`];
  if (!patterns.some((p) => stderr.includes(p))) {
    throw new Error(
      `ASSERT stderr: expected JSONL type ${type}\n--- stderr ---\n${stderr}`,
    );
  }
}
