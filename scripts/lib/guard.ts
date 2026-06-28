import os from "node:os";

export type HostPlatform = "linux" | "mac" | "win";
export type HostArch = "x86_64" | "aarch64";

export function hostArch(): HostArch {
  switch (os.arch()) {
    case "x64":
      return "x86_64";
    case "arm64":
      return "aarch64";
    default:
      throw new Error(`unsupported architecture: ${os.arch()}`);
  }
}

export function hostPlatform(): HostPlatform {
  switch (os.platform()) {
    case "linux":
      return "linux";
    case "darwin":
      return "mac";
    case "win32":
      return "win";
    default:
      throw new Error(`unsupported platform: ${os.platform()}`);
  }
}

export function requirePlatform(platform: HostPlatform): void {
  const host = hostPlatform();
  if (host !== platform) {
    throw new Error(`must run on ${platform} (host is ${host})`);
  }
}
