import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { $ } from "zx";

const ENTITLEMENTS = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.get-task-allow</key>
  <true/>
</dict>
</plist>`;

export async function signGuardianBin(bin: string): Promise<void> {
  if (!fs.existsSync(bin)) {
    throw new Error(`missing binary to sign: ${bin}`);
  }
  const entitlements = path.join(
    os.tmpdir(),
    `guardian-entitlements-${process.pid}.plist`,
  );
  fs.writeFileSync(entitlements, ENTITLEMENTS);
  try {
    await $`codesign -s - -f --entitlements ${entitlements} ${bin}`;
  } finally {
    fs.rmSync(entitlements, { force: true });
  }
}

async function stageSignedTool(
  destDir: string,
  destName: string,
  srcName: string,
): Promise<string> {
  const which = await $`command -v ${srcName}`.quiet();
  const src = which.stdout.trim();
  const dest = path.join(destDir, destName);
  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, dest);
  await signGuardianBin(dest);
  return dest;
}

export async function stageSignedCurl(destDir: string): Promise<string> {
  return stageSignedTool(destDir, "guardian-curl", "curl");
}

export async function stageSignedEnv(destDir: string): Promise<void> {
  await stageSignedTool(destDir, "guardian-env", "env");
}

export async function stageSignedPrintenv(destDir: string): Promise<void> {
  await stageSignedTool(destDir, "guardian-printenv", "printenv");
}

export async function prepareMacSmokePath(binDir: string): Promise<string> {
  const signed = await stageSignedCurl(binDir);
  fs.copyFileSync(signed, path.join(binDir, "curl"));
  await stageSignedEnv(binDir);
  await stageSignedPrintenv(binDir);
  return `${binDir}${path.delimiter}${process.env.PATH ?? ""}`;
}
