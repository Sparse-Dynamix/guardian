import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import http2 from "node:http2";
import type { IncomingMessage } from "node:http";
import os from "node:os";
import path from "node:path";

const MANIFEST_PREFIX = "GUARDIAN_TEST_SERVERS ";
const IMAGE_SWAP_BODY = "# Image description\n\n(swapped by TPF mock)\n";
const DEFAULT_ORIGIN_HOST =
  os.platform() === "darwin" ? "127.0.0.1" : "127.0.0.2";
const MINIMAL_PNG = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49,
  0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
  0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44,
  0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d,
  0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42,
  0x60, 0x82,
]);

export interface TestServersConfig {
  tpfSwapBody?: string;
  tpfRejectNeedle?: string;
  sseEvents?: string[];
}

export interface TestServersManifest {
  tpf: {
    baseUrl: string;
    filterUrl: string;
    passUrl: string;
    rejectUrl: string;
    swapUrl: string;
    imageSwapUrl: string;
    partialUrl: string;
  };
  http: {
    baseUrl: string;
    getUrl: string;
    postUrl: string;
    imagePngUrl: string;
  };
  http2: {
    baseUrl: string;
    getUrl: string;
  };
  http2c: {
    baseUrl: string;
    getUrl: string;
  };
  sse: { baseUrl: string };
  ipv6: { baseUrl: string };
  originCaPem: string;
}

export interface TestServers extends TestServersManifest {
  close: () => Promise<void>;
}

interface RecordedTpfRequest {
  pathAndQuery: string;
  bodyBase64: string;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function listen(
  server: http.Server | http2.Http2Server | http2.Http2SecureServer,
  host: string,
): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error(`failed to bind on ${host}`));
        return;
      }
      resolve(addr.port);
    });
  });
}

function closeServer(
  server: http.Server | http2.Http2Server | http2.Http2SecureServer,
): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

function configFromEnv(): TestServersConfig {
  const sseRaw =
    process.env.GUARDIAN_TEST_SSE_EVENTS ?? "smoke-sse-alpha,smoke-sse-beta";
  return {
    tpfSwapBody: process.env.GUARDIAN_TEST_TPF_SWAP_BODY ?? "SWAPPED_BODY",
    tpfRejectNeedle: process.env.GUARDIAN_TEST_TPF_REJECT_NEEDLE,
    sseEvents: sseRaw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  };
}

function originHostFromEnv(): string {
  return process.env.GUARDIAN_TEST_ORIGIN_HOST ?? DEFAULT_ORIGIN_HOST;
}

function createOriginTlsMaterial(
  tmpDir: string,
  originHost: string,
): {
  caPemPath: string;
  certPem: string;
  keyPem: string;
} {
  const caKeyPath = path.join(tmpDir, "ca-key.pem");
  const caPemPath = path.join(tmpDir, "origin-ca.pem");
  const serverKeyPath = path.join(tmpDir, "server-key.pem");
  const serverCertPath = path.join(tmpDir, "server-cert.pem");
  const csrPath = path.join(tmpDir, "server.csr");
  const opensslCnfPath = path.join(tmpDir, "openssl.cnf");
  fs.writeFileSync(
    opensslCnfPath,
    [
      "[req]",
      "distinguished_name = req_distinguished_name",
      "[req_distinguished_name]",
      "",
    ].join("\n"),
  );

  execFileSync("openssl", [
    "req",
    "-config",
    opensslCnfPath,
    "-x509",
    "-newkey",
    "rsa:2048",
    "-keyout",
    caKeyPath,
    "-out",
    caPemPath,
    "-days",
    "1",
    "-nodes",
    "-subj",
    "/CN=Guardian Test Origin CA",
  ]);
  execFileSync("openssl", [
    "req",
    "-config",
    opensslCnfPath,
    "-newkey",
    "rsa:2048",
    "-keyout",
    serverKeyPath,
    "-out",
    csrPath,
    "-nodes",
    "-subj",
    `/CN=${originHost}`,
  ]);
  const extPath = path.join(tmpDir, "server-ext.cnf");
  fs.writeFileSync(
    extPath,
    [
      "[v3_req]",
      `subjectAltName = IP:${originHost}`,
      "keyUsage = digitalSignature, keyEncipherment",
      "extendedKeyUsage = serverAuth",
      "",
    ].join("\n"),
  );
  execFileSync("openssl", [
    "x509",
    "-req",
    "-in",
    csrPath,
    "-CA",
    caPemPath,
    "-CAkey",
    caKeyPath,
    "-CAcreateserial",
    "-out",
    serverCertPath,
    "-days",
    "1",
    "-sha256",
    "-extfile",
    extPath,
    "-extensions",
    "v3_req",
  ]);

  return {
    caPemPath,
    certPem: fs.readFileSync(serverCertPath, "utf8"),
    keyPem: fs.readFileSync(serverKeyPath, "utf8"),
  };
}

function jsonGetResponse(reqUrl: string, protocol: string): string {
  return JSON.stringify({
    url: reqUrl,
    protocol,
    headers: { Host: new URL(reqUrl).host },
  });
}

export async function startTestServers(
  config: TestServersConfig = configFromEnv(),
): Promise<TestServers> {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "guardian-test-servers-"),
  );
  const originHost = originHostFromEnv();
  const { caPemPath, certPem, keyPem } = createOriginTlsMaterial(
    tmpDir,
    originHost,
  );
  const tpfRequests: RecordedTpfRequest[] = [];
  const swapBody = config.tpfSwapBody ?? "SWAPPED_BODY";
  const rejectNeedle = config.tpfRejectNeedle;
  const sseEvents = config.sseEvents ?? ["smoke-sse-alpha", "smoke-sse-beta"];

  const blockedJson = (
    stage: string,
    reason: string,
    detail?: string,
  ): string =>
    JSON.stringify({
      error: "content_blocked",
      stage,
      reason,
      detail,
    });

  const handleTpfFilter = (
    req: IncomingMessage,
    res: http.ServerResponse,
    pathOnly: string,
    body: Buffer,
  ) => {
    const rawUrl = req.url ?? "";
    const query = new URLSearchParams(
      rawUrl.includes("?") ? (rawUrl.split("?")[1] ?? "") : "",
    );
    const legacyMode =
      pathOnly === "/pass"
        ? "pass"
        : pathOnly === "/reject"
          ? "reject"
          : pathOnly === "/swap"
            ? "swap"
            : pathOnly === "/image-swap"
              ? "image-swap"
              : null;
    const mockMode = query.get("mock") ?? legacyMode;

    if (pathOnly === "/api/filter" && !query.get("url")?.trim()) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("url query parameter is required");
      return;
    }

    if (rejectNeedle && body.includes(rejectNeedle)) {
      const payload = blockedJson(
        "chunk_moderation",
        "Content rejected by mock needle",
        rejectNeedle,
      );
      res.writeHead(406, {
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(payload)),
      });
      res.end(payload);
      return;
    }

    if (mockMode === "reject") {
      const payload = blockedJson(
        "chunk_moderation",
        "All content chunks flagged",
        "mock reject",
      );
      res.writeHead(406, {
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(payload)),
      });
      res.end(payload);
      return;
    }

    if (mockMode === "partial") {
      const partial = "PARTIAL_SAFE_MD";
      res.writeHead(206, {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Length": String(Buffer.byteLength(partial)),
      });
      res.end(partial);
      return;
    }

    if (mockMode === "image-swap") {
      if (!body.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) {
        res.writeHead(400);
        res.end("expected PNG body");
        return;
      }
      const bytes = Buffer.byteLength(IMAGE_SWAP_BODY);
      res.writeHead(200, {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Length": String(bytes),
      });
      res.end(IMAGE_SWAP_BODY);
      return;
    }

    if (mockMode === "swap" || query.get("format") === "md") {
      res.writeHead(200, {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Length": String(Buffer.byteLength(swapBody)),
      });
      res.end(swapBody);
      return;
    }

    res.writeHead(200, { "Content-Length": "0" });
    res.end();
  };

  const tpfServer = http.createServer(async (req, res) => {
    const pathOnly = (req.url ?? "").split("?")[0] ?? "";
    if (req.method === "GET" && pathOnly === "/_debug/requests") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(tpfRequests));
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405);
      res.end();
      return;
    }
    const body = await readBody(req);
    tpfRequests.push({
      pathAndQuery: req.url ?? "",
      bodyBase64: body.toString("base64"),
    });

    if (
      pathOnly === "/api/filter" ||
      pathOnly === "/pass" ||
      pathOnly === "/reject" ||
      pathOnly === "/swap" ||
      pathOnly === "/image-swap"
    ) {
      handleTpfFilter(req, res, pathOnly, body);
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const httpServer = http.createServer(async (req, res) => {
    const host = req.headers.host ?? originHost;
    const reqUrl = `http://${host}${req.url ?? "/"}`;
    const pathOnly = (req.url ?? "").split("?")[0] ?? "";

    if (pathOnly === "/get" && req.method === "GET") {
      const body = jsonGetResponse(reqUrl, "http/1.1");
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(body)),
        Connection: "close",
      });
      res.end(body);
      return;
    }
    if (pathOnly === "/post" && req.method === "POST") {
      const raw = await readBody(req);
      const body = JSON.stringify({
        data: raw.toString("base64"),
        json: null,
        url: reqUrl,
      });
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": String(Buffer.byteLength(body)),
        Connection: "close",
      });
      res.end(body);
      return;
    }
    if (pathOnly === "/image/png" && req.method === "GET") {
      res.writeHead(200, {
        "Content-Type": "image/png",
        "Content-Length": String(MINIMAL_PNG.length),
        Connection: "close",
      });
      res.end(MINIMAL_PNG);
      return;
    }
    res.writeHead(404);
    res.end();
  });

  let http2Port = 0;
  let http2cPort = 0;
  const http2cServer = http2.createServer((req, res) => {
    const pathOnly = (req.url ?? "").split("?")[0] ?? "";
    if (pathOnly === "/get" && req.method === "GET") {
      const reqUrl = `http://${originHost}:${http2cPort}/get`;
      const body = jsonGetResponse(reqUrl, "h2");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  const http2Server = http2.createSecureServer(
    {
      key: keyPem,
      cert: certPem,
      allowHTTP1: true,
    },
    (req, res) => {
      const pathOnly = (req.url ?? "").split("?")[0] ?? "";
      if (pathOnly === "/get" && req.method === "GET") {
        const reqUrl = `https://${originHost}:${http2Port}/get`;
        const body = jsonGetResponse(reqUrl, "h2");
        res.writeHead(200, { "content-type": "application/json" });
        res.end(body);
        return;
      }
      res.writeHead(404);
      res.end();
    },
  );

  const sseServer = http.createServer((_req, res) => {
    const body = sseEvents.map((e) => `data: ${e}\n\n`).join("");
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Transfer-Encoding": "chunked",
      Connection: "close",
    });
    res.write(`${body.length.toString(16)}\r\n${body}\r\n`);
    res.end("0\r\n\r\n");
  });

  const ipv6Server = http.createServer((_req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/plain",
      "Content-Length": "11",
      Connection: "close",
    });
    res.end("ipv6-works");
  });

  const tpfPort = await listen(tpfServer, "127.0.0.1");
  let httpPort = 0;
  let ssePort = 0;
  let ipv6Port = 0;
  const ipv6Host = `::ffff:${originHost}`;
  try {
    httpPort = await listen(httpServer, originHost);
    http2Port = await listen(http2Server, originHost);
    http2cPort = await listen(http2cServer, originHost);
    ssePort = await listen(sseServer, originHost);
    ipv6Port = await listen(ipv6Server, ipv6Host);
  } catch (err) {
    await Promise.allSettled([
      closeServer(tpfServer),
      closeServer(httpServer),
      closeServer(http2Server),
      closeServer(http2cServer),
      closeServer(sseServer),
      closeServer(ipv6Server),
    ]);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    throw err;
  }

  const tpfBase = `http://127.0.0.1:${tpfPort}`;
  const httpBase = `http://${originHost}:${httpPort}`;
  const http2Base = `https://${originHost}:${http2Port}`;
  const http2cBase = `http://${originHost}:${http2cPort}`;
  const sseBase = `http://${originHost}:${ssePort}`;
  const ipv6Base = `http://[${ipv6Host}]:${ipv6Port}`;

  const manifest: TestServersManifest = {
    tpf: {
      baseUrl: tpfBase,
      filterUrl: `${tpfBase}/api/filter`,
      passUrl: `${tpfBase}/api/filter`,
      rejectUrl: `${tpfBase}/api/filter?mock=reject`,
      swapUrl: `${tpfBase}/api/filter?mock=swap`,
      imageSwapUrl: `${tpfBase}/api/filter?mock=image-swap`,
      partialUrl: `${tpfBase}/api/filter?mock=partial`,
    },
    http: {
      baseUrl: httpBase,
      getUrl: `${httpBase}/get`,
      postUrl: `${httpBase}/post`,
      imagePngUrl: `${httpBase}/image/png`,
    },
    http2: {
      baseUrl: http2Base,
      getUrl: `${http2Base}/get`,
    },
    http2c: {
      baseUrl: http2cBase,
      getUrl: `${http2cBase}/get`,
    },
    sse: { baseUrl: sseBase },
    ipv6: { baseUrl: ipv6Base },
    originCaPem: caPemPath,
  };

  return {
    ...manifest,
    close: async () => {
      await Promise.all([
        closeServer(tpfServer),
        closeServer(httpServer),
        closeServer(http2Server),
        closeServer(http2cServer),
        closeServer(sseServer),
        closeServer(ipv6Server),
      ]);
      fs.rmSync(tmpDir, { recursive: true, force: true });
    },
  };
}

const isChildMain =
  process.argv[1]?.includes("test-servers") &&
  process.env.GUARDIAN_TEST_SERVERS_CHILD === "1";

if (isChildMain) {
  const servers = await startTestServers(configFromEnv());
  const { close: _close, ...manifest } = servers;
  process.stdout.write(`${MANIFEST_PREFIX}${JSON.stringify(manifest)}\n`);
  const shutdown = async () => {
    await servers.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
