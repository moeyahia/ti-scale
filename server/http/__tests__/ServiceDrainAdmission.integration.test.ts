import { describe, expect, test } from "bun:test";
import { createServer } from "node:http";
import { Agent, request } from "node:http";
import express from "express";
import { ServiceDrainAdmission } from "../ServiceDrainAdmission";

interface HttpResult {
  readonly status: number;
  readonly connection: string | undefined;
  readonly body: string;
}

function send(port: number, agent: Agent): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const outgoing = request({
      agent,
      host: "127.0.0.1",
      port,
      path: "/api/v2/mutation",
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": "2" },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode ?? 0,
        connection: response.headers.connection,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    outgoing.once("error", reject);
    outgoing.end("{}");
  });
}

describe("ServiceDrainAdmission", () => {
  test("rejects a mutation on an already-open keep-alive connection with 503 and Connection: close", async () => {
    const admission = new ServiceDrainAdmission();
    const app = express();
    app.use(admission.middleware);
    app.post("/api/v2/mutation", (_request, response) => response.status(200).json({ accepted: true }));
    const server = createServer(app);
    let connections = 0;
    server.on("connection", () => { connections += 1; });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No keep-alive fixture address");
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });

    try {
      expect(await send(address.port, agent)).toMatchObject({ status: 200 });
      expect(connections).toBe(1);
      admission.beginDrain();
      const rejected = await send(address.port, agent);
      expect(rejected).toMatchObject({ status: 503, connection: "close" });
      expect(JSON.parse(rejected.body)).toMatchObject({
        error: {
          code: "ti_scale_service_draining",
          retryable: true,
        },
      });
      expect(connections).toBe(1);
    } finally {
      agent.destroy();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});
