import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

import fastifySse from "@fastify/sse";
import fastifyWebsocket from "@fastify/websocket";
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from "fastify";

const MANIFEST_PREFIX = "GUARDIAN_TEST_SERVERS ";
const IMAGE_SWAP_BODY = "# Image description\n\n(swapped by TPF mock)\n";
const DEFAULT_ORIGIN_HOST = "127.0.0.2";
const LOOPBACK_HOST = "127.0.0.1";

const MINIMAL_PNG = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49,
  0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
  0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44,
  0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d,
  0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42,
  0x60, 0x82,
]);

interface SseMessage {
  id?: string;
  event?: string;
  data: string | Record<string, number>;
}

/** Default SSE events for streaming TPF tests (event/id/data shape). */
const DEFAULT_SSE_MESSAGES: SseMessage[] = [
  { id: "0", event: "ping", data: { id: 0 } },
  { id: "1", event: "ping", data: { id: 1 } },
];

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
    loopbackGetUrl: string;
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
  sse: { baseUrl: string; streamUrl: string };
  wss: { baseUrl: string; echoUrl: string };
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

function firstNonLoopbackIPv4(): string | undefined {
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) {
        return entry.address;
      }
    }
  }
  return undefined;
}

/** Connect target for MITM (127/8 bypasses the Frida hook). */
function originHost(): string {
  return (
    process.env.GUARDIAN_TEST_ORIGIN_HOST ??
    firstNonLoopbackIPv4() ??
    DEFAULT_ORIGIN_HOST
  );
}

function configFromEnv(): TestServersConfig {
  const sseRaw = process.env.GUARDIAN_TEST_SSE_EVENTS;
  return {
    tpfSwapBody: process.env.GUARDIAN_TEST_TPF_SWAP_BODY ?? "SWAPPED_BODY",
    tpfRejectNeedle: process.env.GUARDIAN_TEST_TPF_REJECT_NEEDLE,
    sseEvents: sseRaw
      ? sseRaw
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : undefined,
  };
}

function resolveSseMessages(config: TestServersConfig): SseMessage[] {
  if (!config.sseEvents?.length) {
    return DEFAULT_SSE_MESSAGES;
  }
  return config.sseEvents.map((data, index) => ({
    id: String(index),
    event: "message",
    data,
  }));
}

function createOriginTlsMaterial(
  tmpDir: string,
  host: string,
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
    `/CN=${host}`,
  ]);
  const extPath = path.join(tmpDir, "server-ext.cnf");
  fs.writeFileSync(
    extPath,
    [
      "[v3_req]",
      `subjectAltName = IP:${host}`,
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

async function listenFastify(
  app: FastifyInstance,
  host: string,
): Promise<number> {
  const address = await app.listen({ port: 0, host });
  return Number(new URL(address).port);
}

function listenHttp(server: http.Server, host: string): Promise<number> {
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

function closeHttp(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function createOriginHttpApp(
  host: string,
  sseMessages: SseMessage[],
): Promise<{ app: FastifyInstance; port: number }> {
  const app = Fastify({ logger: false });
  await app.register(fastifySse);

  app.get("/get", async (request, reply) => {
    const reqUrl = `http://${request.headers.host ?? host}${request.url}`;
    return reply
      .header("connection", "close")
      .type("application/json")
      .send(jsonGetResponse(reqUrl, "http/1.1"));
  });

  app.post("/post", async (request, reply) => {
    const reqUrl = `http://${request.headers.host ?? host}${request.url}`;
    const raw = request.body;
    const bytes =
      typeof raw === "string"
        ? Buffer.from(raw)
        : Buffer.isBuffer(raw)
          ? raw
          : Buffer.from(JSON.stringify(raw ?? ""));
    return reply
      .header("connection", "close")
      .type("application/json")
      .send(
        JSON.stringify({
          data: bytes.toString("base64"),
          json: null,
          url: reqUrl,
        }),
      );
  });

  app.get("/image/png", async (_request, reply) => {
    return reply
      .header("connection", "close")
      .type("image/png")
      .send(MINIMAL_PNG);
  });

  app.get("/sse", { sse: true }, async (_request, reply) => {
    for (const message of sseMessages) {
      await reply.sse.send({
        id: message.id,
        event: message.event,
        data: message.data,
      });
    }
  });

  const port = await listenFastify(app, "0.0.0.0");
  return { app, port };
}

async function createHttp2App(
  host: string,
  keyPem: string,
  certPem: string,
  tls: boolean,
): Promise<{ app: FastifyInstance; port: number }> {
  const app = Fastify({
    logger: false,
    http2: true,
    ...(tls
      ? {
          https: {
            key: keyPem,
            cert: certPem,
            allowHTTP1: true,
          },
        }
      : {}),
  });

  app.get("/get", async (request, reply) => {
    const scheme = tls ? "https" : "http";
    const reqUrl = `${scheme}://${request.headers.host ?? host}${request.url}`;
    return reply.type("application/json").send(jsonGetResponse(reqUrl, "h2"));
  });

  const port = await listenFastify(app, "0.0.0.0");
  return { app, port };
}

async function createWssEchoApp(
  keyPem: string,
  certPem: string,
): Promise<{ app: FastifyInstance; port: number }> {
  const app = Fastify({
    logger: false,
    https: { key: keyPem, cert: certPem, allowHTTP1: true },
  });
  await app.register(fastifyWebsocket);

  app.get("/", { websocket: true }, (socket) => {
    socket.on("message", (data, isBinary) => {
      socket.send(data, { binary: isBinary });
    });
  });

  const port = await listenFastify(app, "0.0.0.0");
  return { app, port };
}

async function createTpfApp(
  swapBody: string,
  rejectNeedle: string | undefined,
  tpfRequests: RecordedTpfRequest[],
): Promise<{ app: FastifyInstance; port: number }> {
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
    pathOnly: string,
    query: URLSearchParams,
    body: Buffer,
    reply: FastifyReply,
  ) => {
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
      return reply
        .code(400)
        .type("text/plain")
        .send("url query parameter is required");
    }

    if (rejectNeedle && body.includes(rejectNeedle)) {
      const payload = blockedJson(
        "chunk_moderation",
        "Content rejected by mock needle",
        rejectNeedle,
      );
      return reply.code(406).type("application/json").send(payload);
    }

    if (mockMode === "reject") {
      const payload = blockedJson(
        "chunk_moderation",
        "All content chunks flagged",
        "mock reject",
      );
      return reply.code(406).type("application/json").send(payload);
    }

    if (mockMode === "partial") {
      return reply
        .code(206)
        .type("text/markdown; charset=utf-8")
        .send("PARTIAL_SAFE_MD");
    }

    if (mockMode === "image-swap") {
      if (!body.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) {
        return reply.code(400).send("expected PNG body");
      }
      return reply
        .code(200)
        .type("text/markdown; charset=utf-8")
        .send(IMAGE_SWAP_BODY);
    }

    if (mockMode === "swap" || query.get("format") === "md") {
      return reply
        .code(200)
        .type("text/markdown; charset=utf-8")
        .send(swapBody);
    }

    return reply.code(200).send("");
  };

  const app = Fastify({ logger: false });
  app.removeAllContentTypeParsers();
  app.addContentTypeParser(
    "*",
    { parseAs: "buffer" },
    (_request, body, done) => {
      done(null, body);
    },
  );

  app.get("/_debug/requests", async () => JSON.stringify(tpfRequests));

  app.post("/*", async (request: FastifyRequest, reply) => {
    const rawUrl = request.url;
    const pathOnly = rawUrl.split("?")[0] ?? "";
    const query = new URLSearchParams(
      rawUrl.includes("?") ? (rawUrl.split("?")[1] ?? "") : "",
    );
    const body = Buffer.isBuffer(request.body)
      ? request.body
      : Buffer.from((request.body as string | undefined) ?? "");

    tpfRequests.push({
      pathAndQuery: rawUrl,
      bodyBase64: body.toString("base64"),
    });

    if (
      pathOnly === "/api/filter" ||
      pathOnly === "/pass" ||
      pathOnly === "/reject" ||
      pathOnly === "/swap" ||
      pathOnly === "/image-swap"
    ) {
      return handleTpfFilter(pathOnly, query, body, reply);
    }

    return reply.code(404).send();
  });

  const port = await listenFastify(app, "127.0.0.1");
  return { app, port };
}

export async function startTestServers(
  config: TestServersConfig = configFromEnv(),
): Promise<TestServers> {
  const tmpDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "guardian-test-servers-"),
  );
  const host = originHost();
  const { caPemPath, certPem, keyPem } = createOriginTlsMaterial(tmpDir, host);
  const tpfRequests: RecordedTpfRequest[] = [];
  const swapBody = config.tpfSwapBody ?? "SWAPPED_BODY";
  const rejectNeedle = config.tpfRejectNeedle;
  const sseMessages = resolveSseMessages(config);

  const ipv6Server = http.createServer((_req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/plain",
      "Content-Length": "11",
      Connection: "close",
    });
    res.end("ipv6-works");
  });

  let httpApp: FastifyInstance | undefined;
  let http2App: FastifyInstance | undefined;
  let http2cApp: FastifyInstance | undefined;
  let wssApp: FastifyInstance | undefined;
  let tpfApp: FastifyInstance | undefined;
  let httpPort = 0;
  let http2Port = 0;
  let http2cPort = 0;
  let wssPort = 0;
  let tpfPort = 0;
  let ipv6Port = 0;
  const ipv6BindHost = `::ffff:${host}`;

  try {
    ({ app: httpApp, port: httpPort } = await createOriginHttpApp(
      host,
      sseMessages,
    ));
    ({ app: http2App, port: http2Port } = await createHttp2App(
      host,
      keyPem,
      certPem,
      true,
    ));
    ({ app: http2cApp, port: http2cPort } = await createHttp2App(
      host,
      keyPem,
      certPem,
      false,
    ));
    ({ app: wssApp, port: wssPort } = await createWssEchoApp(keyPem, certPem));
    ({ app: tpfApp, port: tpfPort } = await createTpfApp(
      swapBody,
      rejectNeedle,
      tpfRequests,
    ));
    ipv6Port = await listenHttp(ipv6Server, ipv6BindHost);
  } catch (err) {
    await Promise.allSettled([
      httpApp?.close(),
      http2App?.close(),
      http2cApp?.close(),
      wssApp?.close(),
      tpfApp?.close(),
      closeHttp(ipv6Server),
    ]);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    throw err;
  }

  const tpfBase = `http://127.0.0.1:${tpfPort}`;
  const httpBase = `http://${host}:${httpPort}`;
  const loopbackHttpBase = `http://${LOOPBACK_HOST}:${httpPort}`;
  const http2Base = `https://${host}:${http2Port}`;
  const http2cBase = `http://${host}:${http2cPort}`;
  const wssBase = `wss://${host}:${wssPort}`;
  const sseStreamUrl = `${httpBase}/sse`;
  const ipv6Base = `http://[${ipv6BindHost}]:${ipv6Port}`;

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
      loopbackGetUrl: `${loopbackHttpBase}/get`,
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
    sse: { baseUrl: httpBase, streamUrl: sseStreamUrl },
    wss: { baseUrl: wssBase, echoUrl: `${wssBase}/` },
    ipv6: { baseUrl: ipv6Base },
    originCaPem: caPemPath,
  };

  return {
    ...manifest,
    close: async () => {
      await Promise.all([
        httpApp?.close(),
        http2App?.close(),
        http2cApp?.close(),
        wssApp?.close(),
        tpfApp?.close(),
        closeHttp(ipv6Server),
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
