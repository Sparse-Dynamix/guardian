import fs from "node:fs";
import path from "node:path";
import { archiveRootName, packTarGz, packZip } from "./archive.ts";
import { hostArch, type HostPlatform } from "./guard.ts";
import {
  GUARDIAN_ENTITLEMENTS_PLIST,
  signGuardianBin,
} from "./mac-codesign.ts";
import { cdRepo, REPO_ROOT } from "./repo.ts";

const BIN: Record<HostPlatform, string> = {
  linux: "guardian",
  mac: "guardian",
  win: "guardian.exe",
};

function packageVersion(): string {
  const pkg = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"),
  ) as { version: string };
  return pkg.version;
}

function copyIfExists(
  srcDir: string,
  destDir: string,
  name: string,
  executable: boolean,
): boolean {
  const src = path.join(srcDir, name);
  if (!fs.existsSync(src)) return false;
  const dest = path.join(destDir, name);
  fs.copyFileSync(src, dest);
  if (executable) fs.chmodSync(dest, 0o755);
  return true;
}

export async function packReleaseArchive(
  platform: HostPlatform,
): Promise<string> {
  cdRepo();

  const releaseDir = path.join(REPO_ROOT, "target", "release");
  const version = packageVersion();
  const arch = hostArch();
  const staging = path.join(
    REPO_ROOT,
    "dist",
    `guardian-${version}-${platform}-${arch}`,
  );
  fs.rmSync(staging, { recursive: true, force: true });
  fs.mkdirSync(staging, { recursive: true });

  if (!copyIfExists(releaseDir, staging, BIN[platform], platform !== "win")) {
    throw new Error(`missing release binary: ${BIN[platform]}`);
  }

  for (const doc of ["LICENSE", "NOTICE.txt"]) {
    const src = path.join(REPO_ROOT, doc);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(staging, doc));
    }
  }

  if (platform === "mac") {
    fs.writeFileSync(
      path.join(staging, "entitlements.plist"),
      GUARDIAN_ENTITLEMENTS_PLIST,
    );
    await signGuardianBin(path.join(staging, "guardian"));
  }

  const distDir = path.join(REPO_ROOT, "dist");
  fs.mkdirSync(distDir, { recursive: true });
  const base = `guardian-${version}-${platform}-${arch}`;
  const rootName = archiveRootName(staging);

  if (platform === "win") {
    const zipPath = path.join(distDir, `${base}.zip`);
    await packZip(staging, zipPath, rootName);
    return zipPath;
  }

  const archive = path.join(distDir, `${base}.tar.gz`);
  await packTarGz(staging, archive, rootName);
  return archive;
}
