#!/usr/bin/env -S node --import tsx
import { spawnSync } from "node:child_process";
import path from "node:path";
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

const result = spawnSync(delegate, args, { stdio: "inherit" });
const status = result.status ?? 1;

if (status === 0 && out && path.basename(out)) {
  const base = path.basename(out);
  if (base === "guardian" || base === "guardian-ws-smoke") {
    await signGuardianBin(out);
    await prepareMacSmokePath(path.dirname(out));
  }
}

process.exit(status);
