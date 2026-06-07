import { spawnSync } from "node:child_process";

function ipv4FromOutput(stdout: string): string | undefined {
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith("ipv4:")) {
      return trimmed.slice("ipv4:".length).split(/\s+/)[0];
    }
    if (trimmed.startsWith("ip_address:")) {
      return trimmed.slice("ip_address:".length).split(/\s+/)[0];
    }
    const token = trimmed.split(/\s+/)[0];
    if (token && /^[\d.]+$/.test(token)) return token;
  }
  return undefined;
}

function run(cmd: string, args: string[]): string | undefined {
  const result = spawnSync(cmd, args, { encoding: "utf8" });
  if (result.status !== 0) return undefined;
  return ipv4FromOutput(result.stdout);
}

export function resolveIpv4(host: string): string | undefined {
  return (
    run("getent", ["ahostsv4", host]) ??
    run("dscacheutil", ["-q", "host", "-a", "name", host]) ??
    run("dig", ["+short", "A", host])
  );
}

export function curlResolveArgs(url: string, host: string): string[] {
  const ip = resolveIpv4(host);
  if (!ip) return [];
  const port = url.startsWith("https://") ? "443" : "80";
  return ["--resolve", `${host}:${port}:${ip}`];
}
