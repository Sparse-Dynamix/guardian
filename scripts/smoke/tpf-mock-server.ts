import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";

export interface TpfMockServer {
  baseUrl: string;
  passUrl: string;
  rejectUrl: string;
  close: () => Promise<void>;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export async function startTpfMockServer(): Promise<TpfMockServer> {
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405);
      res.end();
      return;
    }
    await readBody(req);
    if (req.url === "/pass") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ safe: true }));
      return;
    }
    if (req.url === "/reject") {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ safe: false }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const addr = server.address();
  if (!addr || typeof addr === "string") {
    throw new Error("failed to bind TPF mock server");
  }

  const baseUrl = `http://127.0.0.1:${addr.port}`;
  return {
    baseUrl,
    passUrl: `${baseUrl}/pass`,
    rejectUrl: `${baseUrl}/reject`,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

const isMain = process.argv[1]?.includes("tpf-mock-server");

if (isMain) {
  const server = await startTpfMockServer();
  console.log(`TPF mock listening at ${server.baseUrl}`);
  console.log(`  pass:   ${server.passUrl}`);
  console.log(`  reject: ${server.rejectUrl}`);
  process.on("SIGINT", async () => {
    await server.close();
    process.exit(0);
  });
}
