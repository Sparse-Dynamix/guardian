import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";

export interface TpfMockServer {
  baseUrl: string;
  passUrl: string;
  rejectUrl: string;
  swapUrl: string;
  imageSwapUrl: string;
  close: () => Promise<void>;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const IMAGE_SWAP_BODY = "# Image description\n\n(swapped by TPF mock)\n";

export async function startTpfMockServer(): Promise<TpfMockServer> {
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405);
      res.end();
      return;
    }
    const body = await readBody(req);
    const path = (req.url ?? "").split("?")[0] ?? "";
    if (path === "/pass") {
      res.writeHead(200, { "Content-Length": "0" });
      res.end();
      return;
    }
    if (path === "/reject") {
      res.writeHead(503, { "Content-Length": "0" });
      res.end();
      return;
    }
    if (path === "/swap") {
      res.writeHead(200, {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Length": String(Buffer.byteLength("SWAPPED_BODY")),
      });
      res.end("SWAPPED_BODY");
      return;
    }
    if (path === "/image-swap") {
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
    swapUrl: `${baseUrl}/swap`,
    imageSwapUrl: `${baseUrl}/image-swap`,
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
  console.log(`  pass:        ${server.passUrl}`);
  console.log(`  reject:      ${server.rejectUrl}`);
  console.log(`  swap:        ${server.swapUrl}`);
  console.log(`  image-swap:  ${server.imageSwapUrl}`);
  process.on("SIGINT", async () => {
    await server.close();
    process.exit(0);
  });
}
