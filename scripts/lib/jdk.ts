import fs from "node:fs";
import path from "node:path";
import { $, usePowerShell } from "zx";
import type { HostPlatform } from "./guard.ts";
import { REPO_ROOT } from "./repo.ts";

if (process.platform === "win32") {
  usePowerShell();
}

const JDK_DIR = path.join(REPO_ROOT, ".cache", "jdk-17");

const TEMURIN: Record<HostPlatform, { url: string; extract: "tar" | "zip" }> = {
  linux: {
    url: "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.15%2B6/OpenJDK17U-jdk_x64_linux_hotspot_17.0.15_6.tar.gz",
    extract: "tar",
  },
  mac: {
    url: "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.15%2B6/OpenJDK17U-jdk_x64_mac_hotspot_17.0.15_6.tar.gz",
    extract: "tar",
  },
  win: {
    url: "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.15%2B6/OpenJDK17U-jdk_x64_windows_hotspot_17.0.15_6.zip",
    extract: "zip",
  },
};

function keytoolPath(): string {
  const name = process.platform === "win32" ? "keytool.exe" : "keytool";
  return path.join(JDK_DIR, "bin", name);
}

export async function ensurePortableJdk(
  platform: HostPlatform,
): Promise<string> {
  if (fs.existsSync(keytoolPath())) {
    return JDK_DIR;
  }

  console.log(
    "Downloading portable JDK 17 for java truststore integration coverage...",
  );
  fs.mkdirSync(path.join(REPO_ROOT, ".cache"), { recursive: true });
  const spec = TEMURIN[platform];

  if (spec.extract === "tar") {
    const archive = path.join(REPO_ROOT, ".cache", "temurin17-jdk.tar.gz");
    await $`curl -fsSL -o ${archive} ${spec.url}`;
    await $`tar -xzf ${archive} -C ${path.join(REPO_ROOT, ".cache")}`;
    fs.rmSync(archive, { force: true });

    const macHome = path.join(
      REPO_ROOT,
      ".cache",
      "jdk-17.0.15+6",
      "Contents",
      "Home",
    );
    const flat = path.join(REPO_ROOT, ".cache", "jdk-17.0.15+6");
    if (fs.existsSync(macHome)) {
      fs.rmSync(JDK_DIR, { recursive: true, force: true });
      fs.renameSync(macHome, JDK_DIR);
    } else if (fs.existsSync(flat)) {
      fs.rmSync(JDK_DIR, { recursive: true, force: true });
      fs.renameSync(flat, JDK_DIR);
    }
  } else {
    const zip = path.join(REPO_ROOT, ".cache", "temurin17-jdk.zip");
    await $`curl -fsSL -o ${zip} ${spec.url}`;
    const extractRoot = path.join(REPO_ROOT, ".cache", "jdk-extract");
    fs.rmSync(extractRoot, { recursive: true, force: true });
    if (process.platform === "win32") {
      await $`powershell.exe -NoProfile -Command Expand-Archive -Path ${zip} -DestinationPath ${extractRoot} -Force`;
    } else {
      await $`unzip -q -o ${zip} -d ${extractRoot}`;
    }
    fs.rmSync(zip, { force: true });
    const extracted = fs
      .readdirSync(extractRoot)
      .find((name) => name.startsWith("jdk-17"));
    if (!extracted) throw new Error("JDK extract failed");
    fs.rmSync(JDK_DIR, { recursive: true, force: true });
    fs.renameSync(path.join(extractRoot, extracted), JDK_DIR);
    fs.rmSync(extractRoot, { recursive: true, force: true });
  }

  if (!fs.existsSync(keytoolPath())) {
    throw new Error(`JDK install failed: missing ${keytoolPath()}`);
  }
  return JDK_DIR;
}

export function applyJdkEnv(javaHome: string): void {
  process.env.JAVA_HOME = javaHome;
  const bin = path.join(javaHome, "bin");
  process.env.PATH = `${bin}${path.delimiter}${process.env.PATH ?? ""}`;
}
