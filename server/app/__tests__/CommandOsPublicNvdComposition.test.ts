import { afterEach, describe, expect, test } from "bun:test";
import express from "express";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PublicNvdToolBoundaryError } from "../../mcp";
import type { RuntimeReadinessSnapshot } from "../RuntimeReadiness";
import { createCommandOsApplication, type CommandOsApplication } from "../CommandOsApplication";
import {
  createTestDatabase,
  MISSION_ID,
  NOW,
  RUN_ID,
  STEP_TWO_ID,
} from "../../../tests/unit/run-intelligence/fixtures";

const REVIEWED_REF = "cveapp_44444444-4444-4444-8444-444444444444";
const directories: string[] = [];
const servers: Server[] = [];
const applications: CommandOsApplication[] = [];

afterEach(async () => {
  await Promise.all(applications.splice(0).map((application) => application.stop()));
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

const runtime: RuntimeReadinessSnapshot = {
  actionBoundaryActive: false,
  delegationEnforced: false,
  noHandsCommanderEnforced: false,
  directCommanderToolsDenied: true,
  specialistAssignmentRequired: true,
  specialistsConfigured: 0,
  providers: [],
  mcp: {
    enabled: false,
    executionMode: "disabled",
    startPermitted: false,
    configuredServers: 0,
    runnableServers: 0,
    missingDependencies: 0,
    missingSecrets: 0,
  },
  eventStream: "healthy",
  secondBrain: "healthy",
  legacyExecutionEnabled: false,
};

describe("CommandOsApplication public NVD composition", () => {
  test("mounts the supplied mission-scoped client without enabling generic execution", async () => {
    const directory = mkdtempSync(join(tmpdir(), "ti-scale-public-nvd-app-"));
    directories.push(directory);
    const databasePath = join(directory, "ti-scale.sqlite");
    const fixture = createTestDatabase(databasePath);
    fixture.prepare(`
      INSERT INTO cve_applicability_records (
        id, mission_id, run_id, cve_id, title, description, component,
        cpe_or_package_json, applicability, confidence, reasoning_summary,
        cvss_json, cwe_json, source_links_json, source_retrieved_at,
        source_version, created_at, updated_at
      ) VALUES (?, ?, ?, 'CVE-2021-44228', 'Reviewed candidate',
        'Locally reviewed candidate', 'log4j-core', '{}', 'possible', 0.72,
        'Official detail is required', '{}', '[]', '[]', ?, 'local-review-v1', ?, ?)
    `).run(REVIEWED_REF, MISSION_ID, RUN_ID, NOW, NOW, NOW);
    fixture.close();

    let clientCalls = 0;
    const authorizations: string[] = [];
    const application = createCommandOsApplication({
      databasePath,
      readinessProviders: () => [],
      runtimeProjection: () => ({ readiness: runtime, agents: [], mcpServers: [] }),
      resolveActor: () => "operator-public-nvd-composition",
      publicNvdDetailClient: {
        async getCveDetails() {
          clientCalls += 1;
          throw new PublicNvdToolBoundaryError(
            "SERVER_ERROR",
            "untrusted sidecar body",
            true,
            3_000,
          );
        },
      },
      resolvePublicNvdDetailActor: () => ({
        id: "operator-public-nvd-composition",
        type: "operator",
      }),
      authorizePublicNvdDetail: (_request, _actor, authorization) => {
        authorizations.push(authorization.capability);
        return true;
      },
      projectionIntervalMs: 60_000,
    });
    applications.push(application);
    const app = express();
    app.use(application.router);
    const server = createServer(app);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");

    const response = await fetch(
      `http://127.0.0.1:${address.port}/api/v2/missions/${MISSION_ID}/runs/${RUN_ID}`
      + `/steps/${STEP_TWO_ID}/intelligence/cves/${REVIEWED_REF}/nvd-detail`,
    );
    const body = await response.json() as any;
    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBe("3");
    expect(body.error).toMatchObject({
      code: "nvd_upstream_error",
      retryable: true,
      details: { targetInteraction: false, executionAuthority: "none" },
    });
    expect(JSON.stringify(body)).not.toContain("untrusted sidecar body");
    expect(clientCalls).toBe(1);
    expect(authorizations).toEqual(["read_public_nvd_detail"]);
    expect(runtime.actionBoundaryActive).toBe(false);
    expect(runtime.mcp.executionMode).toBe("disabled");
  });
});
