import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "./repo.ts";

const RUNTIME: Record<HostOs, { lib: string; name: string }> = {
  linux: { lib: "libfrida-core.so", name: "libfrida-core.so" },
  mac: { lib: "libfrida-core.dylib", name: "libfrida-core.dylib" },
  win: { lib: "frida-core.dll", name: "frida-core.dll" },
};

type HostOs = "linux" | "mac" | "win";

function findFridaOut(): string | undefined {
  const buildRoot = path.join(REPO_ROOT, "target", "release", "build");
  if (!fs.existsSync(buildRoot)) return undefined;

  for (const entry of fs.readdirSync(buildRoot)) {
    if (!entry.startsWith("frida-sys-")) continue;
    const out = path.join(buildRoot, entry, "out", RUNTIME.linux.lib);
    if (fs.existsSync(out)) return out;
    const macOut = path.join(buildRoot, entry, "out", RUNTIME.mac.lib);
    if (fs.existsSync(macOut)) return macOut;
    const winOut = path.join(buildRoot, entry, "out", RUNTIME.win.lib);
    if (fs.existsSync(winOut)) return winOut;
  }
  return undefined;
}

export function stageFridaRuntime(os: HostOs): void {
  const src = findFridaOut();
  const destDir = path.join(REPO_ROOT, "target", "release");
  const destName = RUNTIME[os].name;
  if (!src) {
    console.log(`  note: ${destName} not found (likely statically linked)`);
    return;
  }
  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, path.join(destDir, destName));
  console.log(`  staged ${destName} -> target/release/`);
}
