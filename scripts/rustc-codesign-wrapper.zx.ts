#!/usr/bin/env -S node --import tsx
import path from "node:path";
import { $ } from "zx";
import { prepareMacSmokePath, signGuardianBin } from "./lib/mac-codesign.ts";

const args = process.argv.slice(2);
let out = "";
for (let i = 0; i < args.length; i++) {
  if (args[i] === "-o" && i + 1 < args.length) {
    out = args[i + 1];
  }
}

const delegate = process.env.CARGO_LLVM_COV_RUSTC_DELEGATE;
if (!delegate) {
  throw new Error(
    "CARGO_LLVM_COV_RUSTC_DELEGATE must be set by cargo llvm-cov show-env",
  );
}

const result = $.sync({ stdio: "inherit", nothrow: true })`${delegate} ${args}`;
const status = result.exitCode ?? 1;

if (status === 0 && out && path.basename(out)) {
  const base = path.basename(out);
  if (
    base === "guardian" ||
    base === "guardian-ws-smoke" ||
    base === "guardian-http-smoke" ||
    base === "guardian-exit-code"
  ) {
    await signGuardianBin(out);
    await prepareMacSmokePath(path.dirname(out));
  }
}

process.exit(status);
