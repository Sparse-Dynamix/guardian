import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";

const repoRoot = path.resolve(import.meta.dirname, "..");
const bypassLibPath = path.join(repoRoot, "assets/connect_bypass_lib.js");
const bypassLibSource = fs.readFileSync(bypassLibPath, "utf8");

function loadBypassLib(): {
  shouldBypassAddress: (sa_family: number, bytes: number[]) => boolean;
} {
  const sandbox: Record<string, unknown> = {};
  vm.runInNewContext(
    `${bypassLibSource}\nthis.shouldBypassAddress = shouldBypassAddress;`,
    sandbox,
  );
  return sandbox as ReturnType<typeof loadBypassLib>;
}

test("IPv4 loopback and unspecified addresses bypass", () => {
  const { shouldBypassAddress } = loadBypassLib();

  assert.equal(shouldBypassAddress(2, [127, 0, 0, 1]), true);
  assert.equal(shouldBypassAddress(2, [127, 0, 0, 2]), true);
  assert.equal(shouldBypassAddress(2, [127, 255, 255, 255]), true);
  assert.equal(shouldBypassAddress(2, [0, 0, 0, 0]), true);
});

test("private IPv4 addresses do not bypass", () => {
  const { shouldBypassAddress } = loadBypassLib();

  assert.equal(shouldBypassAddress(2, [10, 0, 0, 1]), false);
  assert.equal(shouldBypassAddress(2, [172, 16, 0, 1]), false);
  assert.equal(shouldBypassAddress(2, [192, 168, 1, 1]), false);
});

test("IPv6 loopback and unspecified addresses bypass", () => {
  const { shouldBypassAddress } = loadBypassLib();

  assert.equal(
    shouldBypassAddress(10, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
    true,
  );
  assert.equal(
    shouldBypassAddress(10, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    true,
  );
});

test("IPv4-mapped loopback and unspecified addresses bypass", () => {
  const { shouldBypassAddress } = loadBypassLib();

  assert.equal(
    shouldBypassAddress(
      10,
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 2],
    ),
    true,
  );
  assert.equal(
    shouldBypassAddress(
      10,
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
    ),
    true,
  );
});

test("IPv4-mapped private addresses do not bypass", () => {
  const { shouldBypassAddress } = loadBypassLib();

  assert.equal(
    shouldBypassAddress(
      10,
      [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
    ),
    false,
  );
});
