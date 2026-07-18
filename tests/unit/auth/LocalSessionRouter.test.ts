import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import type { Server } from "node:http";
import { createLocalSessionRouter } from "../../../server/auth/LocalSessionRouter";
import { LocalSessionAuth, V2_CSRF_COOKIE, V2_SESSION_COOKIE } from "../../../server/auth/LocalSessionAuth";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  })));
});

async function endpoint(): Promise<string> {
  const app = express();
  app.use(express.json());
  app.use(createLocalSessionRouter({
    auth: new LocalSessionAuth({
      operatorToken: "ti-scale-router-test-operator-token",
      actorId: "router-test-operator",
    }),
    secureCookies: false,
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Local session test server did not bind a TCP port");
  return `http://127.0.0.1:${address.port}`;
}

describe("local session cookie deletion", () => {
  test("expires both isolated V2 cookies at the epoch with their original paths", async () => {
    const origin = await endpoint();
    const response = await fetch(`${origin}/api/v2/auth/session`, { method: "DELETE" });
    expect(response.status).toBe(200);

    const header = response.headers.get("set-cookie") ?? "";
    expect(header).toContain(`${V2_SESSION_COOKIE}=`);
    expect(header).toContain(`${V2_CSRF_COOKIE}=`);
    expect(header).toContain("Path=/api/v2");
    expect(header).toContain("Path=/");
    expect(header.match(/Expires=Thu, 01 Jan 1970 00:00:00 GMT/gu)?.length).toBe(2);
    expect(header).not.toContain("Max-Age=0");
  });
});
