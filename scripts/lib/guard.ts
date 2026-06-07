import os from "node:os";

export type HostPlatform = "linux" | "mac" | "win";

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
