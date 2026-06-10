import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";

const repoRoot = path.resolve(import.meta.dirname, "..");
const libPath = path.join(repoRoot, "assets/connect_handshake_lib.js");
const libSource = fs.readFileSync(libPath, "utf8");

function loadHandshakeLib(): {
  evaluateConnectResponse: (bytes: number[]) => {
    ok: boolean;
    reason: string;
    status?: number;
    leftover: number[];
  };
} {
  const sandbox: Record<string, unknown> = {};
  vm.runInNewContext(
    `${libSource}\nthis.evaluateConnectResponse = evaluateConnectResponse;`,
    sandbox,
  );
  return sandbox as ReturnType<typeof loadHandshakeLib>;
}

function asciiBytes(s: string): number[] {
  return [...s].map((c) => c.charCodeAt(0));
}

test("CONNECT 200 with binary leftover", () => {
  const { evaluateConnectResponse } = loadHandshakeLib();
  const verdict = evaluateConnectResponse(
    asciiBytes("HTTP/1.1 200 OK\r\n\r\n").concat([0x16, 0x03, 0x01]),
  );
  assert.equal(verdict.ok, true);
  assert.equal(verdict.status, 200);
  assert.deepEqual(verdict.leftover, [0x16, 0x03, 0x01]);
});

test("CONNECT 503 is rejected", () => {
  const { evaluateConnectResponse } = loadHandshakeLib();
  const verdict = evaluateConnectResponse(
    asciiBytes("HTTP/1.1 503 Service Unavailable\r\n\r\n"),
  );
  assert.equal(verdict.ok, false);
  assert.equal(verdict.status, 503);
  assert.equal(verdict.reason, "non_success");
});

test("malformed status line is rejected", () => {
  const { evaluateConnectResponse } = loadHandshakeLib();
  const verdict = evaluateConnectResponse(asciiBytes("NOT HTTP\r\n\r\n"));
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, "bad_status_line");
});

test("incomplete headers are rejected", () => {
  const { evaluateConnectResponse } = loadHandshakeLib();
  const verdict = evaluateConnectResponse(asciiBytes("HTTP/1.1 200 OK\r\n"));
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, "incomplete");
});

test("oversized header without terminator is rejected", () => {
  const { evaluateConnectResponse } = loadHandshakeLib();
  const verdict = evaluateConnectResponse(
    Array.from({ length: 5000 }, () => 0x41),
  );
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, "incomplete");
});
