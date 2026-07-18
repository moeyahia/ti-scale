import { afterEach, describe, expect, test } from "bun:test";
import type { SqliteDatabase } from "../../db";
import { PageCaptureService } from "../PageCaptureService";
import { PageCaptureError } from "../types";
import { decodePageCaptureCursor } from "../validation";
import {
  AGENT_ID,
  ASSET_ID,
  CONTENT_HASH,
  EVIDENCE_ID,
  FOREIGN_ARTIFACT_ID,
  FOREIGN_MISSION_ID,
  FULL_PAGE_ID,
  MISSION_ID,
  NOW,
  RUN_ID,
  SCREENSHOT_HASH,
  SCREENSHOT_ID,
  SERVICE_ID,
  createPageCaptureFixtureDatabase,
  validPageCaptureInput,
} from "./fixtures";

const databases: SqliteDatabase[] = [];
const actor = { id: "operator-page-capture", type: "operator" } as const;

function harness(): { readonly database: SqliteDatabase; readonly service: PageCaptureService } {
  const database = createPageCaptureFixtureDatabase();
  databases.push(database);
  return { database, service: new PageCaptureService(database, () => new Date(NOW)) };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

function expectCode(operation: () => unknown, code: string): void {
  try {
    operation();
    throw new Error(`Expected ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(PageCaptureError);
    expect((error as PageCaptureError).code).toBe(code);
  }
}

describe("PageCaptureService", () => {
  test("records only a supplied capture result with canonical scope, provenance, and gallery projection", () => {
    const { database, service } = harness();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (() => { throw new Error("Network access is forbidden in page-capture ingestion"); }) as unknown as typeof fetch;
    try {
      const created = service.create(validPageCaptureInput({
        url: "https://PORTAL.example.test/app/login?view=compact&lang=en",
      }), actor);
      expect(created).toMatchObject({
        missionId: MISSION_ID,
        runId: RUN_ID,
        assetNodeId: ASSET_ID,
        serviceNodeId: SERVICE_ID,
        normalizedUrl: "https://portal.example.test/app/login?lang=en&view=compact",
        responseStatus: 200,
        title: "Customer Portal Sign In",
        contentHash: CONTENT_HASH,
        screenshotHash: SCREENSHOT_HASH,
        redactionState: "not_required",
        gallery: {
          label: "Customer Portal Sign In",
          previewArtifactId: SCREENSHOT_ID,
          fullPageArtifactId: FULL_PAGE_ID,
          previewAvailable: true,
        },
      });
      expect(created.screenshot).toEqual({
        artifactId: SCREENSHOT_ID,
        contentHash: SCREENSHOT_HASH,
        mediaType: "image/png",
        byteSize: 12_400,
      });
      expect(created.related).toEqual({
        evidenceIds: [EVIDENCE_ID],
        observationIds: ["observation-page-capture"],
        findingIds: ["finding-page-capture"],
      });
      expect(created).not.toHaveProperty("storageUri");
      expect(service.get(MISSION_ID, created.id)).toEqual(created);
      expect(service.list({ missionId: MISSION_ID, runId: RUN_ID })).toEqual({ items: [created] });

      expect((database.prepare("SELECT COUNT(*) AS count FROM page_captures").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE resource_type = 'page_capture'").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM events WHERE event_type = 'intelligence.page_capture.created'").get() as { count: number }).count).toBe(1);
      expect((database.prepare("SELECT COUNT(*) AS count FROM event_outbox WHERE topic = 'intelligence.page-captures'").get() as { count: number }).count).toBe(1);
      const event = database.prepare("SELECT summary, payload_json FROM events WHERE event_type = 'intelligence.page_capture.created'").get() as {
        readonly summary: string;
        readonly payload_json: string;
      };
      expect(event.summary).toContain("recorded an authorized page capture");
      expect(event.payload_json).not.toContain("storage_uri");
      expect(event.payload_json).not.toContain("artifacts-v2/");
      expect(event.payload_json).not.toContain("lang=en");
      const audit = database.prepare("SELECT details_json FROM audit_records WHERE resource_type = 'page_capture'").get() as {
        readonly details_json: string;
      };
      expect(audit.details_json).not.toContain("lang=en");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("provides stable keyset pagination and withholds unreviewed gallery previews", () => {
    const { service } = harness();
    const older = service.create(validPageCaptureInput({
      contentHash: "1".repeat(64),
      title: "Older capture",
      capturedAt: "2026-07-16T17:57:00.000Z",
      redactionState: "quarantined",
    }), actor);
    const newer = service.create(validPageCaptureInput({
      contentHash: "2".repeat(64),
      title: "Newer capture",
      capturedAt: "2026-07-16T17:58:00.000Z",
      redactionState: "pending",
    }), actor);
    expect(older.gallery).toMatchObject({ previewArtifactId: null, fullPageArtifactId: null, previewAvailable: false });
    expect(newer.gallery).toMatchObject({ previewArtifactId: null, fullPageArtifactId: null, previewAvailable: false });

    const first = service.list({ missionId: MISSION_ID, limit: 1 });
    expect(first.items.map((item) => item.id)).toEqual([newer.id]);
    expect(first.nextCursor).toBeString();
    const second = service.list({ missionId: MISSION_ID, limit: 1, cursor: decodePageCaptureCursor(first.nextCursor!) });
    expect(second.items.map((item) => item.id)).toEqual([older.id]);
    expect(second.nextCursor).toBeUndefined();
  });

  test("rejects unsafe URLs, prohibited targets, credential metadata, and unverified authorization without persistence", () => {
    const { database, service } = harness();
    expectCode(
      () => service.create(validPageCaptureInput({ url: "https://portal.example.test/app/admin/users" }), actor),
      "page_capture_target_prohibited",
    );
    expectCode(
      () => service.create(validPageCaptureInput({ url: "https://user:password@portal.example.test/app/login" }), actor),
      "unsafe_page_capture_url",
    );
    expectCode(
      () => service.create(validPageCaptureInput({ url: "https://portal.example.test/app/login?access_token=secret-value" }), actor),
      "page_capture_sensitive_url_rejected",
    );
    expectCode(
      () => service.create(validPageCaptureInput({
        site: { securityHeaders: [{ name: "set-cookie", value: "session=private" }] },
      }), actor),
      "unsafe_page_capture_metadata",
    );
    database.prepare("UPDATE missions SET authorization_status = 'revoked' WHERE id = ?").run(MISSION_ID);
    expectCode(
      () => service.create(validPageCaptureInput(), actor),
      "page_capture_authorization_unverified",
    );
    expect((database.prepare("SELECT COUNT(*) AS count FROM page_captures").get() as { count: number }).count).toBe(0);
    expect((database.prepare("SELECT COUNT(*) AS count FROM audit_records WHERE resource_type = 'page_capture'").get() as { count: number }).count).toBe(0);
  });

  test("rejects cross-mission artifacts and nodes, hash mismatch, plan ambiguity, actor spoofing, and finding links without supplied evidence", () => {
    const { service } = harness();
    expectCode(
      () => service.create(validPageCaptureInput({
        screenshot: { artifactId: FOREIGN_ARTIFACT_ID, sha256: "e".repeat(64) },
      }), actor),
      "page_capture_artifact_scope_mismatch",
    );
    expectCode(
      () => service.create(validPageCaptureInput({ assetNodeId: "asset-page-capture-foreign" }), actor),
      "page_capture_topology_scope_mismatch",
    );
    expectCode(
      () => service.create(validPageCaptureInput({
        screenshot: { artifactId: SCREENSHOT_ID, sha256: "f".repeat(64) },
      }), actor),
      "page_capture_artifact_hash_mismatch",
    );
    expectCode(
      () => service.create(validPageCaptureInput({ planId: undefined }), actor),
      "invalid_page_capture_plan_scope",
    );
    expectCode(
      () => service.create(validPageCaptureInput(), { id: "another-agent", type: "agent" }),
      "page_capture_actor_mismatch",
    );
    expectCode(
      () => service.create(validPageCaptureInput({ evidenceIds: [] }), actor),
      "page_capture_finding_evidence_required",
    );
    expectCode(
      () => service.create(validPageCaptureInput({
        fullPageScreenshot: undefined,
      }), actor),
      "full_page_artifact_required",
    );
  });

  test("prevents duplicate immutable captures and cross-mission detail disclosure", () => {
    const { service } = harness();
    const created = service.create(validPageCaptureInput(), actor);
    expectCode(() => service.create(validPageCaptureInput(), actor), "page_capture_already_exists");
    expectCode(() => service.get(FOREIGN_MISSION_ID, created.id), "page_capture_not_found");
  });
});
