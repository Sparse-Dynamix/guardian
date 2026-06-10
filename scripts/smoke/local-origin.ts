import http from "node:http";
import type { Server } from "node:http";

export interface LocalOrigin {
  baseUrl: string;
  close: () => Promise<void>;
}

export async function startLocalOrigin(
  kind: "sse" | "ipv6",
): Promise<LocalOrigin> {
  if (kind === "sse") {
    const body = "data: smoke-sse-alpha\n\ndata: smoke-sse-beta\n\n";
    const server = http.createServer((_req, res) => {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Transfer-Encoding": "chunked",
        Connection: "close",
      });
      res.write(`${body.length.toString(16)}\r\n${body}\r\n`);
      res.end("0\r\n\r\n");
    });
    await listen(server, "127.0.0.2");
    const port = (server.address() as { port: number }).port;
    return {
      baseUrl: `http://127.0.0.2:${port}`,
      close: () => closeServer(server),
    };
  }

  const server = http.createServer((_req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/plain",
      "Content-Length": "11",
      Connection: "close",
    });
    res.end("ipv6-works");
  });
  await listen(server, "::ffff:127.0.0.2");
  const port = (server.address() as { port: number }).port;
  return {
    baseUrl: `http://[::ffff:127.0.0.2]:${port}`,
    close: () => closeServer(server),
  };
}

function listen(server: Server, host: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => resolve());
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}
