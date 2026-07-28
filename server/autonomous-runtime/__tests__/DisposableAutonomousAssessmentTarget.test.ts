import { describe, expect, test } from "bun:test";
import {
  DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST,
  DISPOSABLE_AUTONOMOUS_ASSESSMENT_PORT,
  DISPOSABLE_AUTONOMOUS_ASSESSMENT_SERVER,
  startDisposableAutonomousAssessmentTarget,
} from "../testing/DisposableAutonomousAssessmentTarget";
import {
  AUTONOMOUS_FULL_TCP_NMAP_PATH,
} from "../AutonomousFullTcpBaseline";
import { deriveAutonomousWebOrigins } from "../AutonomousWebSurfaceBaseline";

describe("DisposableAutonomousAssessmentTarget", () => {
  test("binds only to 127.0.0.2, serves bounded non-redirecting HTTP, and closes cleanly", async () => {
    const fixture = await startDisposableAutonomousAssessmentTarget();
    const origin = fixture.origin;
    try {
      expect(fixture.host).toBe(DISPOSABLE_AUTONOMOUS_ASSESSMENT_HOST);
      expect(fixture.port).toBe(DISPOSABLE_AUTONOMOUS_ASSESSMENT_PORT);
      expect(origin).toBe(`http://127.0.0.2:${fixture.port}`);

      const root = await fetch(`${origin}/`, {
        redirect: "manual",
        signal: AbortSignal.timeout(2_000),
      });
      expect(root.status).toBe(200);
      expect(root.headers.get("location")).toBeNull();
      expect(root.headers.get("server")).toBe(
        DISPOSABLE_AUTONOMOUS_ASSESSMENT_SERVER,
      );
      expect(await root.text()).toContain(
        "Reviewed local Autonomous assessment target",
      );

      const options = await fetch(`${origin}/`, {
        method: "OPTIONS",
        redirect: "manual",
        signal: AbortSignal.timeout(2_000),
      });
      expect(options.status).toBe(204);
      expect(options.headers.get("allow")).toBe("GET, HEAD, OPTIONS");

      const trace = await fetch(`${origin}/`, {
        method: "TRACE",
        redirect: "manual",
        signal: AbortSignal.timeout(2_000),
      });
      expect(trace.status).toBe(405);
      expect(fixture.requests().map(({ method }) => method)).toEqual([
        "GET",
        "OPTIONS",
        "TRACE",
      ]);
    } finally {
      await fixture.close();
    }

    await expect(fetch(`${origin}/`, {
      signal: AbortSignal.timeout(1_000),
    })).rejects.toThrow();
    await expect(fixture.close()).resolves.toBeUndefined();
  });

  test("is recognized by the reviewed Nmap binding as one evidence-eligible HTTP origin", async () => {
    const fixture = await startDisposableAutonomousAssessmentTarget();
    try {
      const child = Bun.spawn([
        AUTONOMOUS_FULL_TCP_NMAP_PATH,
        "-n",
        "-Pn",
        "-sT",
        "--open",
        "-p",
        String(fixture.port),
        "-sV",
        "--version-light",
        "--",
        fixture.host,
      ], {
        stdout: "pipe",
        stderr: "pipe",
      });
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ]);
      expect(exitCode).toBe(0);
      expect(stderr).toBe("");
      const row = stdout.split("\n").find((line) =>
        line.startsWith(`${fixture.port}/tcp`));
      expect(row).toBeDefined();
      const match = row?.match(/^\d+\/tcp\s+open\s+(\S+)/u);
      expect(match?.[1]).toBe("http");
      expect(deriveAutonomousWebOrigins(fixture.host, [{
        port: fixture.port,
        transport: "tcp",
        state: "open",
        service: match?.[1] ?? null,
        version: null,
      }])).toEqual([`${fixture.origin}/`]);
    } finally {
      await fixture.close();
    }
  }, 15_000);

  test("injects exactly one loopback-only curl transport failure and then recovers", async () => {
    const fixture = await startDisposableAutonomousAssessmentTarget({
      recoverableHttpMetadataFailureOnce: true,
    });
    const invoke = async () => {
      const child = Bun.spawn([
        "/usr/bin/curl",
        "--head",
        "--silent",
        "--show-error",
        "--max-time",
        "2",
        "--output",
        "/dev/null",
        `${fixture.origin}/`,
      ], {
        stdout: "pipe",
        stderr: "pipe",
      });
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ]);
      return { stdout, stderr, exitCode };
    };
    try {
      const failed = await invoke();
      expect([52, 56]).toContain(failed.exitCode);
      expect(failed.stdout).toBe("");
      expect(failed.stderr).toMatch(/empty reply|recv failure|connection reset/iu);

      const recovered = await invoke();
      expect(recovered).toEqual({ stdout: "", stderr: "", exitCode: 0 });
      expect(fixture.failureReceipt()).toEqual({
        enabled: true,
        injectedFailureCount: 1,
        recoveredCurlHeadCount: 1,
      });
      expect(fixture.requests().filter(({ outcome }) =>
        outcome === "transient_reset")).toHaveLength(1);
      expect(fixture.requests().filter(({ outcome }) =>
        outcome === "served")).toHaveLength(1);
    } finally {
      await fixture.close();
    }
  });
});
