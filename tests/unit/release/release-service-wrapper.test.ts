import { describe, expect, test } from "bun:test";
import { createServer } from "node:http";
import {
  createReleaseGuardedServer,
  RELEASE_GUARDED_HEALTH_PROTOCOL,
  RELEASE_SERVICE_WRAPPER_APPLICATION_ENTRYPOINT,
  releaseServiceApplicationExecSpec,
  releaseServiceWrapperSelfReport,
  runReleaseServiceWrapper,
} from "../../../scripts/release/service-wrapper";

const INVOCATION_ID = "a".repeat(32);

async function unusedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not allocate test port");
  await new Promise<void>((resolve, reject) => {
    try { server.close(() => resolve()); }
    catch (error) { reject(error); }
  });
  return address.port;
}

describe("stable release service wrapper", () => {
  test("reports an exact versioned protocol", () => {
    expect(releaseServiceWrapperSelfReport()).toEqual({
      schemaVersion: "ti-scale.release-service-wrapper.v2",
      guardedHealthSchema: RELEASE_GUARDED_HEALTH_PROTOCOL,
      applicationEntrypoint: RELEASE_SERVICE_WRAPPER_APPLICATION_ENTRYPOINT,
      applicationExecMode: "atomic_direct_entrypoint",
    });
  });

  test("atomically execs the real server entrypoint without a package-script parent", () => {
    const specification = releaseServiceApplicationExecSpec({
      environment: {
        HOME: "/nonexistent",
        TI_SCALE_PORT: "",
        TI_SCALE_SERVE_STATIC: "false",
      },
    });
    expect(specification.executable).toBe("/usr/local/bin/bun");
    expect(specification.argv).toEqual([
      "/usr/local/bin/bun",
      "/opt/ti-scale/server/index.ts",
    ]);
    expect(specification.argv).not.toContain("server");
    expect(specification.argv).not.toContain("run");
    expect(specification.environment).toMatchObject({
      HOME: "/nonexistent",
      TI_SCALE_PORT: "3132",
      TI_SCALE_SERVE_STATIC: "true",
    });

    const overridden = releaseServiceApplicationExecSpec({
      applicationPath: "/srv/ti-scale-fixture",
      bunPath: "/opt/bun/bin/bun",
      environment: { TI_SCALE_PORT: "43141" },
    });
    expect(overridden.argv).toEqual([
      "/opt/bun/bin/bun",
      "/srv/ti-scale-fixture/server/index.ts",
    ]);
    expect(overridden.environment.TI_SCALE_PORT).toBe("43141");
    expect(() => releaseServiceApplicationExecSpec({ applicationPath: "relative" }))
      .toThrow("must be absolute");
  });

  test("execs the application immediately when no release fence exists", async () => {
    const events: string[] = [];
    await expect(runReleaseServiceWrapper({
      invocationId: INVOCATION_ID,
      barrierExists: () => false,
      createGuardedServer: async () => {
        events.push("guarded");
        return { port: 3132, close: async () => undefined };
      },
      execApplication: () => {
        events.push("exec");
        throw new Error("exec sentinel");
      },
    })).rejects.toThrow("exec sentinel");
    expect(events).toEqual(["exec"]);
  });

  test("keeps the app dormant, closes the listener, then execs after the fence opens", async () => {
    const events: string[] = [];
    const observations = [true, true, false];
    await expect(runReleaseServiceWrapper({
      invocationId: INVOCATION_ID,
      pollIntervalMs: 10,
      barrierExists: () => observations.shift() ?? false,
      createGuardedServer: async () => {
        events.push("guarded");
        return {
          port: 3132,
          close: async () => { events.push("closed"); },
        };
      },
      sleep: async () => { events.push("poll"); },
      execApplication: () => {
        events.push("exec");
        throw new Error("exec sentinel");
      },
    })).rejects.toThrow("exec sentinel");
    expect(events).toEqual(["guarded", "poll", "closed", "exec"]);
  });

  test("fails closed and closes guarded HTTP when barrier inspection fails", async () => {
    let inspections = 0;
    const events: string[] = [];
    await expect(runReleaseServiceWrapper({
      invocationId: INVOCATION_ID,
      pollIntervalMs: 10,
      barrierExists: () => {
        inspections += 1;
        if (inspections === 1) return true;
        throw new Error("invalid root-owned barrier");
      },
      createGuardedServer: async () => ({
        port: 3132,
        close: async () => { events.push("closed"); },
      }),
      execApplication: () => {
        events.push("exec");
        throw new Error("must not execute");
      },
    })).rejects.toThrow("invalid root-owned barrier");
    expect(events).toEqual(["closed"]);
  });

  test("serves only exact health/readiness requests and fences every other request", async () => {
    const port = await unusedPort();
    const guarded = await createReleaseGuardedServer(INVOCATION_ID, "127.0.0.1", port);
    try {
      for (const path of ["/api/v2/health", "/api/v2/system/readiness"]) {
        const response = await fetch(`http://127.0.0.1:${String(port)}${path}`);
        expect(response.status).toBe(200);
        expect(response.headers.get("connection")).toBe("close");
        expect(await response.json()).toEqual({
          schemaVersion: RELEASE_GUARDED_HEALTH_PROTOCOL,
          status: "journal_guarded",
          mode: "release_startup_mutation_fence",
          mutationFenced: true,
          invocationId: INVOCATION_ID,
        });
      }

      const head = await fetch(`http://127.0.0.1:${String(port)}/api/v2/health`, { method: "HEAD" });
      expect(head.status).toBe(200);
      expect(await head.text()).toBe("");

      for (const request of [
        { path: "/api/v2/missions", method: "GET" },
        { path: "/api/v2/health?probe=1", method: "GET" },
        { path: "/api/v2/health", method: "POST" },
      ]) {
        const response = await fetch(`http://127.0.0.1:${String(port)}${request.path}`, {
          method: request.method,
        });
        expect(response.status).toBe(503);
        expect(response.headers.get("connection")).toBe("close");
        const body = await response.json() as Record<string, unknown>;
        expect(body.code).toBe("RELEASE_STARTUP_MUTATION_FENCED");
        expect(body.retryable).toBe(true);
      }
    } finally {
      await guarded.close();
    }
  });

  test("rejects non-systemd identity and non-loopback guarded binding", async () => {
    await expect(runReleaseServiceWrapper({
      invocationId: "missing",
      barrierExists: () => false,
      execApplication: () => { throw new Error("must not execute"); },
    })).rejects.toThrow("requires a systemd invocation identity");
    await expect(createReleaseGuardedServer(INVOCATION_ID, "0.0.0.0", 3132))
      .rejects.toThrow("may bind only to 127.0.0.1");
  });
});
