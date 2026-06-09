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

export function assertStdoutContains(file: string, substring: string): void {
  const stdout = fs.readFileSync(file, "utf8");
  if (!stdout.includes(substring)) {
    throw new Error(
      `ASSERT stdout: expected to contain ${JSON.stringify(substring)}\n--- stdout ---\n${stdout}`,
    );
  }
}

export function assertStdoutNotContains(
  file: string,
  substrings: string[],
): void {
  const stdout = fs.readFileSync(file, "utf8");
  for (const substring of substrings) {
    if (stdout.includes(substring)) {
      throw new Error(
        `ASSERT stdout: expected not to contain ${JSON.stringify(substring)}\n--- stdout ---\n${stdout}`,
      );
    }
  }
}

export function assertStdoutEquals(file: string, expected: string): void {
  const stdout = fs.readFileSync(file, "utf8");
  if (stdout !== expected) {
    throw new Error(
      `ASSERT stdout: expected ${JSON.stringify(expected)}, got ${JSON.stringify(stdout)}`,
    );
  }
}

export function assertContentType(file: string, expected: string): void {
  const stdout = fs.readFileSync(file, "utf8");
  const re = new RegExp(`content-type:\\s*${expected}`, "i");
  if (!re.test(stdout)) {
    throw new Error(
      `ASSERT headers: expected Content-Type ${JSON.stringify(expected)}\n--- stdout ---\n${stdout}`,
    );
  }
}

export function assertNoJsonlOnStderr(stderrFile: string): void {
  const stderr = fs.readFileSync(stderrFile, "utf8");
  if (/^\{.*"type":/m.test(stderr)) {
    throw new Error(
      `ASSERT stderr: expected no JSONL lines\n--- stderr ---\n${stderr}`,
    );
  }
}
