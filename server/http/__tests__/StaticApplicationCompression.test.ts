import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request, type IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { brotliDecompressSync } from "node:zlib";
import express from "express";
import {
  createStaticApplicationCompression,
  STATIC_COMPRESSION_THRESHOLD_BYTES,
} from "../StaticApplicationCompression";

interface HttpResult {
  readonly status: number;
  readonly headers: IncomingHttpHeaders;
  readonly body: Buffer;
}

const fixtureRoots: string[] = [];

afterEach(() => {
  for (const root of fixtureRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function send(
  port: number,
  path: string,
  acceptEncoding: string,
): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const outgoing = request({
      host: "127.0.0.1",
      port,
      path,
      method: "GET",
      headers: { "Accept-Encoding": acceptEncoding },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
    });
    outgoing.once("error", reject);
    outgoing.end();
  });
}

describe("static application compression", () => {
  test("serves large browser assets with Brotli and retains identity delivery", async () => {
    const root = mkdtempSync(join(tmpdir(), "ti-scale-static-compression-"));
    fixtureRoots.push(root);
    const source = `export const titanium = ${JSON.stringify("titanium ".repeat(2_000))};\n`;
    expect(Buffer.byteLength(source)).toBeGreaterThan(STATIC_COMPRESSION_THRESHOLD_BYTES);
    writeFileSync(join(root, "application.js"), source);

    const app = express();
    app.use(createStaticApplicationCompression());
    app.use(express.static(root));
    const server = createServer(app);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No static-compression fixture address");

    try {
      const compressed = await send(address.port, "/application.js", "br, gzip");
      expect(compressed.status).toBe(200);
      expect(compressed.headers["content-encoding"]).toBe("br");
      expect(compressed.headers.vary).toContain("Accept-Encoding");
      expect(brotliDecompressSync(compressed.body).toString("utf8")).toBe(source);
      expect(compressed.body.byteLength).toBeLessThan(Buffer.byteLength(source));

      const identity = await send(address.port, "/application.js", "identity");
      expect(identity.status).toBe(200);
      expect(identity.headers["content-encoding"]).toBeUndefined();
      expect(identity.body.toString("utf8")).toBe(source);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  });

  test("never compresses API or event-stream responses even when mounted before them", async () => {
    const app = express();
    app.use(createStaticApplicationCompression());
    app.get("/api/v2/probe", (_request, response) => {
      response.json({ payload: "api ".repeat(2_000) });
    });
    app.get("/events", (_request, response) => {
      response.setHeader("Content-Type", "text/event-stream");
      response.end(`event: heartbeat\ndata: ${"stream ".repeat(2_000)}\n\n`);
    });
    const server = createServer(app);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No static-compression fixture address");

    try {
      const api = await send(address.port, "/api/v2/probe", "br, gzip");
      expect(api.status).toBe(200);
      expect(api.headers["content-encoding"]).toBeUndefined();
      expect(JSON.parse(api.body.toString("utf8"))).toMatchObject({
        payload: expect.stringContaining("api api"),
      });

      const events = await send(address.port, "/events", "br, gzip");
      expect(events.status).toBe(200);
      expect(events.headers["content-type"]).toStartWith("text/event-stream");
      expect(events.headers["content-encoding"]).toBeUndefined();
      expect(events.body.toString("utf8")).toStartWith("event: heartbeat");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});
