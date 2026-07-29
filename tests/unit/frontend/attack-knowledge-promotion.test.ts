/// <reference lib="dom" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  createAttackKnowledgePromotionKey,
  fetchAttackKnowledgeBundles,
  fetchAttackKnowledgeEvidence,
  previewAttackKnowledgePromotion,
  promoteAttackKnowledge,
} from "../../../src/data/api/attackKnowledgePromotion";
import { parseAttackKnowledgeEvidencePage } from "../../../src/domain/schemas/attackKnowledgePromotion";
import type { AttackKnowledgeBundleSummary } from "../../../src/domain/types/attackKnowledgePromotion";
import { exactResetSemantics } from "../../../src/features/brain/AttackKnowledgePromotionReview";

const fingerprint = "a".repeat(64);
const reviewHash = "b".repeat(64);
const contentHash = "c".repeat(64);
const evidenceId = "evidence-bound-one";

const bundle: AttackKnowledgeBundleSummary = {
  bundleId: "bundle-one",
  bundleFingerprint: fingerprint,
  status: "staged",
  kind: "operational_hazard",
  candidates: { total: 12, reviewed: 12, pending: 0, rejected: 0 },
  exactProcedureCounts: {
    attempts: 3,
    reproducibleOutcomes: 2,
    evidenceItems: 2,
    exactResets: 2,
    operatorReportedAggregateResetMinimum: 11,
  },
  boundEvidenceCount: 2,
  firstObservedAt: "2026-07-13T02:00:00.000Z",
  lastObservedAt: "2026-07-15T10:00:00.000Z",
  promotedReceipt: null,
};

interface Call { readonly path: string; readonly init?: RequestInit }
let originalFetch: typeof globalThis.fetch;
let originalDocument: PropertyDescriptor | undefined;
let calls: Call[];
let responses: unknown[];

beforeEach(() => {
  originalFetch = globalThis.fetch;
  originalDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  calls = [];
  responses = [];
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { cookie: "ti_scale_csrf=promotion-csrf" },
  });
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ path: typeof input === "string" ? input : input.toString(), init });
    const payload = responses.shift();
    if (payload === undefined) throw new Error("No mocked promotion response remains");
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "Content-Type": "application/json", "X-Request-Id": "promotion-request-one" },
    });
  }) as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalDocument) Object.defineProperty(globalThis, "document", originalDocument);
  else Reflect.deleteProperty(globalThis, "document");
});

describe("Attack Knowledge Promotion operator contract", () => {
  test("keeps exact procedure resets distinct from the unattributed overall minimum", () => {
    expect(exactResetSemantics(bundle)).toEqual([
      {
        label: "Exact resets attributable to this procedure",
        value: "2",
        explanation: "Counted only when a reset receipt is bound to this exact procedure version and evidence lineage.",
      },
      {
        label: "Overall operator-reported reset minimum",
        value: "At least 11",
        explanation: "Context only. This overall minimum is not silently assigned to this procedure.",
      },
    ]);
  });

  test("rejects an evidence-picker payload that is not canonically verified", () => {
    expect(() => parseAttackKnowledgeEvidencePage({
      schemaVersion: "2.4",
      bundleId: "bundle-one",
      bundleFingerprint: fingerprint,
      totalReturned: 1,
      items: [{
        id: evidenceId,
        contentHash,
        evidenceType: "http_response",
        acquiredAt: "2026-07-15T10:00:00.000Z",
        verificationState: "unverified",
      }],
    })).toThrow("verificationState must be verified");
  });

  test("uses only server-returned bundle routes and preserves the deliberate promotion key", async () => {
    const evidencePayload = {
      schemaVersion: "2.4",
      bundleId: "bundle-one",
      bundleFingerprint: fingerprint,
      totalReturned: 1,
      items: [{
        id: evidenceId,
        contentHash,
        evidenceType: "http_response",
        acquiredAt: "2026-07-15T10:00:00.000Z",
        verificationState: "verified",
      }],
    };
    const previewPayload = {
      schemaVersion: "2.4",
      ready: false,
      replay: false,
      reviewHash,
      blockers: [{ code: "candidate_unreviewed", message: "One candidate still needs operator review" }],
      review: {
        bundle: {
          id: "bundle-one",
          semanticFingerprint: fingerprint,
          kind: "operational_hazard",
          exactProcedureCounts: bundle.exactProcedureCounts,
          firstObservedAt: bundle.firstObservedAt,
          lastObservedAt: bundle.lastObservedAt,
        },
        candidates: [],
        edges: [],
        operationalHazardProfile: null,
        verification: { minimumEvidenceItems: 1, evidence: evidencePayload.items },
      },
    };
    const receiptPayload = {
      schemaVersion: "2.4",
      status: "materialized",
      receiptId: "akprom-one",
      bundleId: "bundle-one",
      reviewHash,
      auditRecordId: "audit-one",
      edgeIds: ["edge-one"],
      hazardProfileNodeId: "hazard-one",
      hazardProfileVersion: 1,
      promotedAt: "2026-07-20T20:00:00.000Z",
    };
    responses.push(
      { schemaVersion: "2.4", items: [bundle], totalReturned: 1 },
      evidencePayload,
      previewPayload,
      receiptPayload,
    );
    const signal = new AbortController().signal;
    await fetchAttackKnowledgeBundles(signal);
    await fetchAttackKnowledgeEvidence(fingerprint, signal);
    await previewAttackKnowledgePromotion(fingerprint, [evidenceId]);
    const key = "promotion-decision-one";
    await promoteAttackKnowledge({
      bundleFingerprint: fingerprint,
      expectedReviewHash: reviewHash,
      verificationEvidenceIds: [evidenceId],
    }, key);

    expect(calls.map(({ path }) => path)).toEqual([
      "/api/v2/brain/attack-knowledge/bundles?status=all",
      `/api/v2/brain/attack-knowledge/bundles/${fingerprint}/evidence`,
      `/api/v2/brain/attack-knowledge/bundles/${fingerprint}/preview`,
      `/api/v2/brain/attack-knowledge/bundles/${fingerprint}/promote`,
    ]);
    expect(new Headers(calls[2]!.init?.headers).get("X-Ti-Scale-CSRF")).toBe("promotion-csrf");
    expect(new Headers(calls[3]!.init?.headers).get("X-Ti-Scale-CSRF")).toBe("promotion-csrf");
    expect(new Headers(calls[3]!.init?.headers).get("Idempotency-Key")).toBe(key);
    expect(JSON.parse(String(calls[3]!.init?.body))).toEqual({
      expectedReviewHash: reviewHash,
      verificationEvidenceIds: [evidenceId],
    });
  });

  test("creates a bounded nonempty mutation key", () => {
    expect(createAttackKnowledgePromotionKey()).toMatch(/^.{8,200}$/u);
  });
});
