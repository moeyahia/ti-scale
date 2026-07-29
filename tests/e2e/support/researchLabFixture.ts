import { createDatabaseConnection } from "../../../server/db";
import { E2E_DATABASE_PATH } from "./environment";

export interface ResearchLabWriteLock {
  release(): void;
}

export interface ResearchCampaignFixtureState {
  readonly status: string;
  readonly updatedAt: string;
  readonly createAuditCount: number;
  readonly stopAuditCount: number;
  readonly charterCount: number;
  readonly experimentCount: number;
}

function databasePath(): string {
  if (!E2E_DATABASE_PATH) throw new Error("Research Lab E2E requires the isolated V2 database path");
  return E2E_DATABASE_PATH;
}

/**
 * Hold a real SQLite write reservation while the browser reaches the mounted
 * Research Lab router. Reads remain available under WAL; the represented
 * mutation reaches BEGIN IMMEDIATE, exhausts the server's bounded busy wait,
 * and returns the real retryable persistence envelope.
 */
export function holdResearchLabWriteLock(): ResearchLabWriteLock {
  const database = createDatabaseConnection({
    filename: databasePath(),
    busyTimeoutMs: 10_000,
    verifyIntegrity: false,
  });
  database.exec("BEGIN IMMEDIATE");
  let released = false;
  return {
    release(): void {
      if (released) return;
      released = true;
      try {
        database.exec("ROLLBACK");
      } finally {
        database.close();
      }
    },
  };
}

/** Advance only the optimistic-concurrency timestamp; no campaign status,
 * charter, experiment, or audit record is fabricated by the fixture. */
export function advanceResearchCampaignVersion(campaignId: string): string {
  const database = createDatabaseConnection({ filename: databasePath(), verifyIntegrity: false });
  try {
    const row = database.prepare("SELECT updated_at FROM research_campaigns WHERE id = ?")
      .get(campaignId) as { readonly updated_at: string } | undefined;
    if (!row) throw new Error(`Research campaign ${campaignId} does not exist`);
    const current = Date.parse(row.updated_at);
    if (!Number.isFinite(current)) throw new Error(`Research campaign ${campaignId} has an invalid timestamp`);
    const updatedAt = new Date(Math.max(current + 1_000, Date.now() + 1_000)).toISOString();
    const result = database.prepare("UPDATE research_campaigns SET updated_at = ? WHERE id = ? AND updated_at = ?")
      .run(updatedAt, campaignId, row.updated_at);
    if (result.changes !== 1) throw new Error(`Research campaign ${campaignId} changed while advancing the fixture version`);
    return updatedAt;
  } finally {
    database.close();
  }
}

export function readResearchCampaignFixtureState(campaignId: string): ResearchCampaignFixtureState {
  const database = createDatabaseConnection({ filename: databasePath(), readonly: true, fileMustExist: true, verifyIntegrity: false });
  try {
    const row = database.prepare(`
      SELECT
        c.status,
        c.updated_at,
        (SELECT COUNT(*) FROM audit_records a WHERE a.resource_id = c.id AND a.action = 'research_campaign.created') AS create_audit_count,
        (SELECT COUNT(*) FROM audit_records a WHERE a.resource_id = c.id AND a.action = 'research_campaign.stopped') AS stop_audit_count,
        (SELECT COUNT(*) FROM research_charters h WHERE h.campaign_id = c.id) AS charter_count,
        (SELECT COUNT(*) FROM experiments e WHERE e.campaign_id = c.id) AS experiment_count
      FROM research_campaigns c WHERE c.id = ?
    `).get(campaignId) as {
      readonly status: string;
      readonly updated_at: string;
      readonly create_audit_count: number;
      readonly stop_audit_count: number;
      readonly charter_count: number;
      readonly experiment_count: number;
    } | undefined;
    if (!row) throw new Error(`Research campaign ${campaignId} does not exist`);
    return {
      status: row.status,
      updatedAt: row.updated_at,
      createAuditCount: row.create_audit_count,
      stopAuditCount: row.stop_audit_count,
      charterCount: row.charter_count,
      experimentCount: row.experiment_count,
    };
  } finally {
    database.close();
  }
}
