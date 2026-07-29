#!/usr/bin/env bun
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import {
  resolveCliDatabasePath,
  resolveCliVaultRoot,
  type TiScaleCliEnvironment,
} from "../app/StandaloneCliConfiguration";
import {
  checkDatabaseIntegrity,
  createDatabaseConnection,
} from "../db";
import { MemoryRepository } from "../memory";
import { withCanonicalWriterLease } from "../maintenance";
import { resolveOperationalHazardObservationKey } from "../memory/OperationalHazardObservationKey";
import { ObsidianVaultBridge, VaultPathPolicy } from "../vault";
import { ApprovedLegacyVaultProjectionService } from "./ApprovedLegacyVaultProjectionService";
import {
  LegacyMigrationService,
  MAX_SETTLE_SECONDS,
  MIN_SETTLE_SECONDS,
} from "./LegacyMigrationService";
import { redactLegacyText } from "./SecretSafety";
import {
  HistoricalHazardEvidenceImportService,
  type HistoricalHazardImportManifest,
} from "./HistoricalHazardEvidenceImportService";
import type { OperationalHazardKnowledge } from "./AttackKnowledgeCompiler";
import {
  HistoricalAttackKnowledgeExtractionService,
} from "./HistoricalAttackKnowledgeExtractionService";
import {
  GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES,
  GenericHistoricalAttackKnowledgeIngestionService,
} from "./GenericHistoricalAttackKnowledgeIngestionService";
import { BoundedAttackKnowledgePreviewAccumulator } from "./BoundedAttackKnowledgePreviewAccumulator";
import { FailedLegacyMigrationReconciliationService } from "./FailedLegacyMigrationReconciliationService";
import { OrphanedHistoricalMigrationLeaseReleaseService } from "./OrphanedHistoricalMigrationLeaseReleaseService";
import { CompletedHistoricalExtractionSealService } from "./CompletedHistoricalExtractionSealService";
import { MigrationMetadataRepository } from "./MigrationMetadataRepository";
import {
  BoundedHistoricalAttackKnowledgeResumeService,
  type BoundedHistoricalAttackKnowledgeResumeResult,
} from "./BoundedHistoricalAttackKnowledgeResumeService";
import { loadHistoricalSqliteSnapshotQuarantineMapping } from "./HistoricalSqliteSnapshotQuarantineMapping";
import {
  loadTrustedHistoricalSourceDeltaExecutionPlan,
} from "./HistoricalSourceDeltaExecutionPlan";

interface ParsedArguments {
  readonly command: string;
  readonly values: Map<string, string[]>;
  readonly flags: Set<string>;
}

function parseArguments(argv: readonly string[]): ParsedArguments {
  const [command = "help", ...rest] = argv;
  const values = new Map<string, string[]>();
  const flags = new Set<string>();
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index]!;
    if (!token.startsWith("--")) throw new Error(`Unexpected argument: ${token}`);
    const key = token.slice(2);
    const next = rest[index + 1];
    if (!next || next.startsWith("--")) {
      flags.add(key);
      continue;
    }
    values.set(key, [...(values.get(key) ?? []), next]);
    index += 1;
  }
  return { command, values, flags };
}

function required(args: ParsedArguments, key: string): string {
  const value = args.values.get(key)?.at(-1);
  if (!value) throw new Error(`--${key} is required`);
  return resolve(value);
}

function databasePath(args: ParsedArguments, environment: TiScaleCliEnvironment): string {
  return resolveCliDatabasePath(args.values.get("db")?.at(-1), environment);
}

function vaultRoot(args: ParsedArguments, environment: TiScaleCliEnvironment): string {
  return resolveCliVaultRoot(args.values.get("vault-root")?.at(-1), environment);
}

function requiredValue(args: ParsedArguments, key: string): string {
  const value = args.values.get(key)?.at(-1)?.trim();
  if (!value) throw new Error(`--${key} is required`);
  return value;
}

function requiredPositiveInteger(args: ParsedArguments, key: string): number {
  const raw = requiredValue(args, key);
  if (!/^\d+$/u.test(raw)) throw new Error(`--${key} must be a positive safe integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`--${key} must be a positive safe integer`);
  }
  return value;
}

function optionalSettleSeconds(args: ParsedArguments): number | undefined {
  if (args.flags.has("settle-seconds")) throw new Error("--settle-seconds requires an integer value");
  const values = args.values.get("settle-seconds") ?? [];
  if (values.length === 0) return undefined;
  if (values.length > 1) throw new Error("--settle-seconds may be supplied only once");
  const raw = values[0]!;
  if (!/^\d+$/u.test(raw)) {
    throw new Error(`--settle-seconds must be an integer between ${MIN_SETTLE_SECONDS} and ${MAX_SETTLE_SECONDS}`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < MIN_SETTLE_SECONDS || value > MAX_SETTLE_SECONDS) {
    throw new Error(`--settle-seconds must be an integer between ${MIN_SETTLE_SECONDS} and ${MAX_SETTLE_SECONDS}`);
  }
  return value;
}

function boundedJson(path: string, label: string): unknown {
  const absolutePath = resolve(path);
  const state = lstatSync(absolutePath);
  if (!state.isFile() || state.isSymbolicLink() || state.size > 2 * 1024 * 1024) {
    throw new Error(`${label} must be a regular, non-link JSON file no larger than 2 MiB`);
  }
  return JSON.parse(readFileSync(absolutePath, "utf8")) as unknown;
}

function configuredHazardKey(
  configuredDatabasePath: string,
  environment: TiScaleCliEnvironment,
): Buffer {
  if (!environment.TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY &&
      !environment.TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE) {
    throw new Error(
      "Historical bundle binding requires an existing TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY or TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE",
    );
  }
  return resolveOperationalHazardObservationKey({
    databasePath: configuredDatabasePath,
    environment,
  });
}

function help(): string {
  return `Ti-Scale data import and maintenance CLI

Usage:
  bun run server/migration/cli.ts migrate [--db PATH] [--source PARENT] [--engagement-root PATH] [--history-root PATH] --output DIR [--dry-run] [--resume ID]
    [--source-retention verified-reference] --acknowledge-verified-reference
    [--brain-projection legacy-engagement|attack-knowledge-only] [--acknowledge-attack-knowledge-only]
    [--settle-seconds 60..86400]
    [--defer-active-source PATH ...] [--acknowledge-active-source-deferrals]
    [--sqlite-snapshot-receipt PATH --sqlite-snapshot-receipt-sha256 SHA256
      --acknowledge-empty-sqlite-snapshot-quarantine]
    [--reviewed-source-delta-plan PATH --reviewed-source-delta-plan-sha256 SHA256
      --reviewed-source-config-sha256 SHA256 --acknowledge-reviewed-source-delta]
    [--bounded-resume]
  bun run server/migration/cli.ts verify [--db PATH]
  bun run server/migration/cli.ts reconcile [--db PATH] --migration-id ID
  bun run server/migration/cli.ts reconcile-failed-preview [--db PATH] --migration-id ID --replacement-migration-id ID
  bun run server/migration/cli.ts reconcile-failed [--db PATH] --migration-id ID --replacement-migration-id ID
    --expected-preview-hash HASH --actor ACTOR --reason TEXT --acknowledge-failed-migration-reconciliation
  bun run server/migration/cli.ts release-orphaned-migration-lease-preview [--db PATH] --lease-id ID --fencing-token TOKEN
  bun run server/migration/cli.ts release-orphaned-migration-lease [--db PATH] --lease-id ID --fencing-token TOKEN
    --expected-preview-hash HASH --actor ACTOR --reason TEXT --acknowledge-orphaned-migration-lease-release
  bun run server/migration/cli.ts seal-completed-extraction-preview [--db PATH] --migration-id ID
  bun run server/migration/cli.ts seal-completed-extraction [--db PATH] --migration-id ID
    --expected-preview-hash HASH --actor ACTOR --reason TEXT --acknowledge-completed-extraction-seal
  bun run server/migration/cli.ts project-vault [--db PATH] [--vault-root ROOT] --migration-id ID --reconciliation-hash HASH --connection ID --dry-run
  bun run server/migration/cli.ts project-vault [--db PATH] [--vault-root ROOT] --migration-id ID --reconciliation-hash HASH --projection-hash HASH --connection ID --approved-by ACTOR --approve-projection
  bun run server/migration/cli.ts hazard-preview [--db PATH] --manifest PATH
  bun run server/migration/cli.ts hazard-stage [--db PATH] --manifest PATH --preview-hash HASH --approved-by ACTOR --approve-stage
  bun run server/migration/cli.ts hazard-reconcile [--db PATH] --job ID
  bun run server/migration/cli.ts hazard-bind-preview [--db PATH] --job ID --knowledge PATH --evidence ID [...] --private-label LABEL [...]
  bun run server/migration/cli.ts hazard-bind [--db PATH] --job ID --knowledge PATH --evidence ID [...] --private-label LABEL [...] --binding-preview-hash HASH --approved-by ACTOR --approve-binding
  bun run server/migration/cli.ts attack-source-review-start [--db PATH] --candidate ID --approved-by ACTOR --reason TEXT --approve-review
  bun run server/migration/cli.ts attack-source-verify [--db PATH] --candidate ID --approved-by ACTOR --reason TEXT --expected-sha256 HASH --approve-verification

Environment fallbacks:
  TI_SCALE_DATABASE_PATH
  TI_SCALE_VAULT_ROOT (project-vault only)

Safety:
  migrate is forward-only and creates no database or source backup.
  verified-reference is mandatory because source-byte copies are disabled; it requires --acknowledge-verified-reference.
  attack-knowledge-only creates only private source inventory plus sanitized extractor candidates; it requires verified-reference and --acknowledge-attack-knowledge-only.
  --source imports safe child directories as engagements; --engagement-root imports that directory as one engagement.
  --history-root imports only deterministically classified runtime/provider history and never infers engagements.
  --dry-run performs discovery, hashing, and a local-only semantic preview in a disposable database.
  project-vault --dry-run is read-only and returns the exact projection hash.
  Vault writes require that hash plus --approve-projection and a fresh filesystem round-trip.
  hazard-preview verifies only the selected bounded manifest and writes nothing.
  hazard-stage retains hash-verified source references, never copies source or manifest bytes, and creates candidates only; it never verifies evidence.
  hazard-bind accepts only independently verified evidence produced from that exact import job.
  Bundle staging never confirms, verifies, or promotes reusable memory candidates.
  Historical source verification is a separate explicit operator action that re-hashes the private local source.
  Orphaned lease release is restricted to the exact historical-engagement importer writer identity. It requires no matching importer process, terminal overlapping migrations with no pending/importing sources, the exact lease ID/fence, and a reviewed preview hash. Service/runtime, maintenance, released, expired, and unknown leases are never eligible.
  --settle-seconds is opt-in. It defers files newer than one migration-start cutoff; included files keep exact revalidation.
  --defer-active-source is a narrow live-tree catch-up boundary. On a new run each exact regular file must be newer than the cutoff or currently held open for write. Repeat the same paths on resume.
  --bounded-resume requires --resume and continues generic extraction from its latest immutable cursor using one closed SQLite connection per page.
  A reviewed source-delta plan is a private mode-0600 exact-file admission. Its file hash, self-hash, configuration, baseline, paths, inode/stat/hash identities, and active-writer state are revalidated before mutation; aggregate planner output alone is never executable.
  reconcile-failed changes only lingering pending/importing child metadata after a newer completed replacement proves the exact source identity and root.
  seal-completed-extraction is narrower: it accepts only the exact post-extraction inventory-drift failure and seals already-completed immutable extraction receipts without rescanning live sources or changing semantic knowledge.
`;
}

async function main(
  argv = process.argv.slice(2),
  environment: TiScaleCliEnvironment = process.env,
): Promise<number> {
  const args = parseArguments(argv);
  if (args.command === "help" || args.flags.has("help")) {
    process.stdout.write(help());
    return 0;
  }
  if (["attack-source-review-start", "attack-source-verify"].includes(args.command)) {
    const configuredDatabasePath = databasePath(args, environment);
    if (!existsSync(configuredDatabasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
    const database = createDatabaseConnection({ filename: configuredDatabasePath, fileMustExist: true });
    try {
      const service = new HistoricalAttackKnowledgeExtractionService(database, {
        receiptHmacKey: configuredHazardKey(configuredDatabasePath, environment),
      });
      const common = {
        candidateId: requiredValue(args, "candidate"),
        actorId: requiredValue(args, "approved-by"),
        reason: requiredValue(args, "reason"),
      };
      if (args.command === "attack-source-review-start") {
        if (!args.flags.has("approve-review")) {
          throw new Error("Historical source review requires --approve-review");
        }
        const result = await withCanonicalWriterLease(database, {
          ownerId: common.actorId,
          operation: "historical-source-review-start",
        }, (handle, leases) => {
          leases.assertActive(handle);
          return service.beginSourceEvidenceReview(common);
        });
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        return 0;
      }
      if (!args.flags.has("approve-verification")) {
        throw new Error("Historical source verification requires --approve-verification");
      }
      const expectedSourceHash = requiredValue(args, "expected-sha256").toLowerCase();
      if (!/^[a-f0-9]{64}$/u.test(expectedSourceHash)) throw new Error("--expected-sha256 must be a lowercase SHA-256");
      const result = await withCanonicalWriterLease(database, {
        ownerId: common.actorId,
        operation: "historical-source-verification",
      }, (handle, leases) => {
        leases.assertActive(handle);
        return service.verifySourceEvidence({ ...common, expectedSourceHash });
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    } finally {
      database.close();
    }
  }
  if (["hazard-preview", "hazard-stage", "hazard-reconcile", "hazard-bind-preview", "hazard-bind"].includes(args.command)) {
    if (args.values.has("backup-root") || args.flags.has("backup-root")) {
      throw new Error("--backup-root is unavailable because historical hazard import is forward-only and creates no backups");
    }
    const configuredDatabasePath = databasePath(args, environment);
    if (!existsSync(configuredDatabasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
    const readonly = args.command === "hazard-preview" || args.command === "hazard-reconcile" || args.command === "hazard-bind-preview";
    const database = createDatabaseConnection({
      filename: configuredDatabasePath,
      readonly,
      fileMustExist: true,
      // Read-only hazard previews already reopen and hash every bounded source.
      // A full multi-gigabyte SQLite quick_check belongs to the explicit
      // `verify` operation, not a request whose contract promises bounded I/O.
      ...(readonly ? { verifyIntegrity: false } : {}),
    });
    try {
      const needsBindingKey = args.command === "hazard-bind-preview" || args.command === "hazard-bind";
      const service = new HistoricalHazardEvidenceImportService(database, {
        ...(needsBindingKey
          ? { receiptHmacKey: configuredHazardKey(configuredDatabasePath, environment) }
          : {}),
      });
      if (args.command === "hazard-preview") {
        const preview = service.preview(boundedJson(required(args, "manifest"), "--manifest"));
        process.stdout.write(`${JSON.stringify(preview, null, 2)}\n`);
        return 0;
      }
      if (args.command === "hazard-stage") {
        if (!args.flags.has("approve-stage")) {
          throw new Error("Historical hazard staging requires --approve-stage after reviewing hazard-preview");
        }
        const actorId = requiredValue(args, "approved-by");
        const result = await withCanonicalWriterLease(database, {
          ownerId: actorId,
          operation: "historical-hazard-stage",
        }, (handle, leases) => {
          leases.assertActive(handle);
          return service.stage({
            manifest: boundedJson(required(args, "manifest"), "--manifest") as HistoricalHazardImportManifest,
            expectedPreviewHash: requiredValue(args, "preview-hash"),
            approvedBy: actorId,
            approvalGranted: true,
          });
        });
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        return 0;
      }
      if (args.command === "hazard-reconcile") {
        process.stdout.write(`${JSON.stringify(service.reconcile(requiredValue(args, "job")), null, 2)}\n`);
        return 0;
      }
      const common = {
        jobId: requiredValue(args, "job"),
        privateLabels: args.values.get("private-label") ?? [],
        canonicalEvidenceIds: args.values.get("evidence") ?? [],
        knowledge: boundedJson(required(args, "knowledge"), "--knowledge") as OperationalHazardKnowledge,
        confidence: 1,
      };
      if (args.command === "hazard-bind-preview") {
        process.stdout.write(`${JSON.stringify(service.previewBundleBinding(common), null, 2)}\n`);
        return 0;
      }
      if (!args.flags.has("approve-binding")) {
        throw new Error("Historical bundle staging requires --approve-binding after reviewing hazard-bind-preview");
      }
      const actorId = requiredValue(args, "approved-by");
      const result = await withCanonicalWriterLease(database, {
        ownerId: actorId,
        operation: "historical-hazard-bind",
      }, (handle, leases) => {
        leases.assertActive(handle);
        return service.bindVerifiedEvidence({
          ...common,
          expectedBindingPreviewHash: requiredValue(args, "binding-preview-hash"),
          approvedBy: actorId,
          approvalGranted: true,
        });
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    } finally {
      database.close();
    }
  }
  if (args.command === "release-orphaned-migration-lease-preview"
      || args.command === "release-orphaned-migration-lease") {
    const configuredDatabasePath = databasePath(args, environment);
    if (!existsSync(configuredDatabasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
    const common = {
      leaseId: requiredValue(args, "lease-id"),
      fencingToken: requiredPositiveInteger(args, "fencing-token"),
    };
    if (args.command === "release-orphaned-migration-lease-preview") {
      const database = createDatabaseConnection({
        filename: configuredDatabasePath,
        readonly: true,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        const preview = new OrphanedHistoricalMigrationLeaseReleaseService(database, {
          databasePath: configuredDatabasePath,
        }).preview(common);
        process.stdout.write(`${JSON.stringify({ status: "ready_for_release", ...preview }, null, 2)}\n`);
        return 0;
      } finally {
        database.close();
      }
    }
    if (!args.flags.has("acknowledge-orphaned-migration-lease-release")) {
      throw new Error("--acknowledge-orphaned-migration-lease-release is required after reviewing the exact preview");
    }
    const database = createDatabaseConnection({
      filename: configuredDatabasePath,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      const result = new OrphanedHistoricalMigrationLeaseReleaseService(database, {
        databasePath: configuredDatabasePath,
      }).release({
        ...common,
        expectedPreviewHash: requiredValue(args, "expected-preview-hash"),
        actorId: requiredValue(args, "actor"),
        reason: requiredValue(args, "reason"),
        acknowledged: true,
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    } finally {
      database.close();
    }
  }
  if (args.command === "reconcile-failed-preview" || args.command === "reconcile-failed") {
    const configuredDatabasePath = databasePath(args, environment);
    if (!existsSync(configuredDatabasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
    const common = {
      failedMigrationId: requiredValue(args, "migration-id"),
      replacementMigrationId: requiredValue(args, "replacement-migration-id"),
    };
    if (args.command === "reconcile-failed-preview") {
      const database = createDatabaseConnection({
        filename: configuredDatabasePath,
        readonly: true,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        const preview = new FailedLegacyMigrationReconciliationService(database).preview(common);
        process.stdout.write(`${JSON.stringify({ status: "ready_for_reconciliation", ...preview }, null, 2)}\n`);
        return 0;
      } finally {
        database.close();
      }
    }
    if (!args.flags.has("acknowledge-failed-migration-reconciliation")) {
      throw new Error("--acknowledge-failed-migration-reconciliation is required after reviewing the exact preview");
    }
    const actorId = requiredValue(args, "actor");
    const database = createDatabaseConnection({
      filename: configuredDatabasePath,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      const service = new FailedLegacyMigrationReconciliationService(database);
      const result = await withCanonicalWriterLease(database, {
        ownerId: actorId,
        operation: "failed-legacy-migration-reconciliation",
      }, (handle, leases) => service.reconcile({
        ...common,
        expectedPreviewHash: requiredValue(args, "expected-preview-hash"),
        actorId,
        reason: requiredValue(args, "reason"),
        acknowledged: true,
      }, { handle, leases }));
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    } finally {
      database.close();
    }
  }
  if (args.command === "seal-completed-extraction-preview" || args.command === "seal-completed-extraction") {
    const configuredDatabasePath = databasePath(args, environment);
    if (!existsSync(configuredDatabasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
    const migrationId = requiredValue(args, "migration-id");
    if (args.command === "seal-completed-extraction-preview") {
      const database = createDatabaseConnection({
        filename: configuredDatabasePath,
        readonly: true,
        fileMustExist: true,
        verifyIntegrity: false,
      });
      try {
        const preview = new CompletedHistoricalExtractionSealService(database).preview({ migrationId });
        process.stdout.write(`${JSON.stringify({ status: "ready_for_seal", ...preview }, null, 2)}\n`);
        return 0;
      } finally {
        database.close();
      }
    }
    if (!args.flags.has("acknowledge-completed-extraction-seal")) {
      throw new Error("--acknowledge-completed-extraction-seal is required after reviewing the exact preview");
    }
    const actorId = requiredValue(args, "actor");
    const database = createDatabaseConnection({
      filename: configuredDatabasePath,
      fileMustExist: true,
      verifyIntegrity: false,
    });
    try {
      const service = new CompletedHistoricalExtractionSealService(database);
      const result = await withCanonicalWriterLease(database, {
        ownerId: actorId,
        operation: "completed-historical-extraction-seal",
      }, (handle, leases) => service.seal({
        migrationId,
        expectedPreviewHash: requiredValue(args, "expected-preview-hash"),
        actorId,
        reason: requiredValue(args, "reason"),
        acknowledged: true,
      }, { handle, leases }));
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    } finally {
      database.close();
    }
  }
  if (args.command === "project-vault") {
    const dryRun = args.flags.has("dry-run");
    if (!dryRun && !args.flags.has("approve-projection")) {
      throw new Error("Vault projection requires --approve-projection after reviewing a dry-run preview");
    }
    const configuredDatabasePath = databasePath(args, environment);
    if (!existsSync(configuredDatabasePath)) throw new Error("Canonical database does not exist; run db:migrate first");
    const configuredVaultRoot = vaultRoot(args, environment);
    if (!existsSync(configuredVaultRoot) || !lstatSync(configuredVaultRoot).isDirectory()) {
      throw new Error("--vault-root must be an existing directory; projection never creates an operator sandbox root");
    }
    const database = createDatabaseConnection({
      filename: configuredDatabasePath,
      readonly: dryRun,
      fileMustExist: true,
    });
    try {
      const bridge = new ObsidianVaultBridge(
        database,
        new MemoryRepository(database),
        new VaultPathPolicy(configuredVaultRoot),
      );
      const service = new ApprovedLegacyVaultProjectionService(database, bridge);
      const previewInput = {
        migrationId: requiredValue(args, "migration-id"),
        expectedReconciliationHash: requiredValue(args, "reconciliation-hash"),
        connectionId: requiredValue(args, "connection"),
      };
      const preview = service.preview(previewInput);
      if (dryRun) {
        process.stdout.write(`${JSON.stringify({
          status: preview.eligibleNodeCount > 0 ? "ready_for_approval" : "no_eligible_nodes",
          dryRun: true,
          migrationId: preview.migrationId,
          reconciliationHash: preview.reconciliationHash,
          projectionHash: preview.projectionHash,
          connection: {
            id: preview.connectionId,
            displayName: preview.connectionDisplayName,
          },
          counts: {
            mapped: preview.mappedNodeCount,
            eligible: preview.eligibleNodeCount,
            excludedByPolicyOrConnectionScope: preview.excludedNodeCount,
          },
        }, null, 2)}\n`);
        return preview.eligibleNodeCount > 0 ? 0 : 2;
      }
      const actorId = requiredValue(args, "approved-by");
      const result = await withCanonicalWriterLease(database, {
        ownerId: actorId,
        operation: "legacy-vault-projection",
      }, (handle, leases) => {
        leases.assertActive(handle);
        return service.project({
          ...previewInput,
          expectedProjectionHash: requiredValue(args, "projection-hash"),
          approvedBy: actorId,
        });
      });
      const attentionRequired = result.export.counts.conflicts > 0
        || result.export.counts.vaultAhead > 0
        || result.export.counts.quarantined > 0;
      const failed = result.export.counts.failed > 0;
      process.stdout.write(`${JSON.stringify({
        status: failed ? "failed" : attentionRequired ? "attention_required" : "completed",
        dryRun: false,
        approvalId: result.approvalId,
        migrationId: preview.migrationId,
        reconciliationHash: preview.reconciliationHash,
        projectionHash: result.projectionHash,
        projectedNodes: result.projectedNodeIds.length,
        export: result.export,
      }, null, 2)}\n`);
      return failed ? 1 : attentionRequired ? 2 : 0;
    } finally {
      database.close();
    }
  }
  if (args.command === "migrate") {
    const roots = args.values.get("source") ?? [];
    const engagementRoots = args.values.get("engagement-root") ?? [];
    const historyRoots = args.values.get("history-root") ?? [];
    if (!roots.length && !engagementRoots.length && !historyRoots.length) {
      throw new Error("At least one --source, --engagement-root, or --history-root path is required");
    }
    const sourceRetention = args.values.get("source-retention")?.at(-1) ?? "verified-reference";
    if (sourceRetention !== "verified-reference") {
      throw new Error("--source-retention must be verified-reference because source backups are disabled by operator policy");
    }
    const brainProjectionMode = args.values.get("brain-projection")?.at(-1) ?? "legacy-engagement";
    if (brainProjectionMode !== "legacy-engagement" && brainProjectionMode !== "attack-knowledge-only") {
      throw new Error("--brain-projection must be legacy-engagement or attack-knowledge-only");
    }
    if (sourceRetention === "verified-reference" && !args.flags.has("acknowledge-verified-reference")) {
      throw new Error("--acknowledge-verified-reference is required because referenced source bytes are not copied or made immutable");
    }
    if (brainProjectionMode === "attack-knowledge-only" && !args.flags.has("acknowledge-attack-knowledge-only")) {
      throw new Error("--acknowledge-attack-knowledge-only is required because target-centric legacy domain and Brain projection is suppressed");
    }
    if (brainProjectionMode === "attack-knowledge-only" && sourceRetention !== "verified-reference") {
      throw new Error("--brain-projection attack-knowledge-only requires --source-retention verified-reference");
    }
    if (historyRoots.length > 0 && brainProjectionMode !== "attack-knowledge-only") {
      throw new Error("--history-root is available only with --brain-projection attack-knowledge-only");
    }
    const settleSeconds = optionalSettleSeconds(args);
    const explicitActiveSourceDeferrals = (args.values.get("defer-active-source") ?? []).map((path) => resolve(path));
    if (args.flags.has("defer-active-source")) {
      throw new Error("--defer-active-source requires a file path");
    }
    if (explicitActiveSourceDeferrals.length > 0 && !args.flags.has("acknowledge-active-source-deferrals")) {
      throw new Error(
        "--acknowledge-active-source-deferrals is required because explicitly deferred files are omitted from this migration receipt",
      );
    }
    if (args.flags.has("acknowledge-active-source-deferrals") && explicitActiveSourceDeferrals.length === 0) {
      throw new Error("--acknowledge-active-source-deferrals requires at least one --defer-active-source path");
    }
    const sqliteReceiptValues = args.values.get("sqlite-snapshot-receipt") ?? [];
    const sqliteReceiptHashValues = args.values.get("sqlite-snapshot-receipt-sha256") ?? [];
    if (args.flags.has("sqlite-snapshot-receipt") || args.flags.has("sqlite-snapshot-receipt-sha256")) {
      throw new Error("SQLite snapshot receipt options require values");
    }
    if (sqliteReceiptValues.length > 1 || sqliteReceiptHashValues.length > 1) {
      throw new Error("Only one receipt-bound empty SQLite snapshot mapping is supported per migration");
    }
    if ((sqliteReceiptValues.length === 1) !== (sqliteReceiptHashValues.length === 1)) {
      throw new Error("--sqlite-snapshot-receipt and --sqlite-snapshot-receipt-sha256 must be supplied together");
    }
    const sqliteSnapshotQuarantineRequested = sqliteReceiptValues.length === 1;
    if (sqliteSnapshotQuarantineRequested
      && !args.flags.has("acknowledge-empty-sqlite-snapshot-quarantine")) {
      throw new Error("--acknowledge-empty-sqlite-snapshot-quarantine is required for receipt-bound content-free custody");
    }
    if (!sqliteSnapshotQuarantineRequested
      && args.flags.has("acknowledge-empty-sqlite-snapshot-quarantine")) {
      throw new Error("SQLite snapshot quarantine acknowledgement requires a receipt and reviewed SHA-256");
    }
    if (sqliteSnapshotQuarantineRequested
      && (sourceRetention !== "verified-reference" || brainProjectionMode !== "attack-knowledge-only")) {
      throw new Error("SQLite snapshot quarantine requires verified-reference attack-knowledge-only migration");
    }
    const configuredSourceRoots = [...roots, ...engagementRoots, ...historyRoots].map((root) => resolve(root));
    const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
    const sqliteSnapshotQuarantineMappings = sqliteSnapshotQuarantineRequested
      ? [await loadHistoricalSqliteSnapshotQuarantineMapping({
        receipt: {
          path: resolve(sqliteReceiptValues[0]!),
          trustRoot: dirname(resolve(sqliteReceiptValues[0]!)),
          expectedSha256: sqliteReceiptHashValues[0]!.trim().toLowerCase(),
          allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
          maximumBytes: 64 * 1024,
        },
        allowedSourceRoots: configuredSourceRoots,
      })]
      : [];
    const reviewedDeltaPlanValues = args.values.get("reviewed-source-delta-plan") ?? [];
    const reviewedDeltaPlanHashValues = args.values.get("reviewed-source-delta-plan-sha256") ?? [];
    const reviewedDeltaConfigHashValues = args.values.get("reviewed-source-config-sha256") ?? [];
    if (args.flags.has("reviewed-source-delta-plan")
      || args.flags.has("reviewed-source-delta-plan-sha256")
      || args.flags.has("reviewed-source-config-sha256")) {
      throw new Error("Reviewed source-delta options require values");
    }
    const reviewedDeltaRequested = reviewedDeltaPlanValues.length > 0
      || reviewedDeltaPlanHashValues.length > 0
      || reviewedDeltaConfigHashValues.length > 0;
    if (reviewedDeltaPlanValues.length > 1 || reviewedDeltaPlanHashValues.length > 1
      || reviewedDeltaConfigHashValues.length > 1) {
      throw new Error("Reviewed source-delta options may each be supplied only once");
    }
    if (reviewedDeltaRequested && (
      reviewedDeltaPlanValues.length !== 1
      || reviewedDeltaPlanHashValues.length !== 1
      || reviewedDeltaConfigHashValues.length !== 1
    )) {
      throw new Error("Reviewed source-delta plan, plan SHA-256, and configuration SHA-256 are required together");
    }
    if (reviewedDeltaRequested && !args.flags.has("acknowledge-reviewed-source-delta")) {
      throw new Error("--acknowledge-reviewed-source-delta is required for exact-file execution");
    }
    if (!reviewedDeltaRequested && args.flags.has("acknowledge-reviewed-source-delta")) {
      throw new Error("Reviewed source-delta acknowledgement requires a sealed plan and hashes");
    }
    if (reviewedDeltaRequested
      && (sourceRetention !== "verified-reference" || brainProjectionMode !== "attack-knowledge-only")) {
      throw new Error("Reviewed source-delta execution requires verified-reference attack-knowledge-only migration");
    }
    const reviewedDeltaConfigSha256 = reviewedDeltaConfigHashValues[0]?.trim().toLowerCase();
    if (reviewedDeltaConfigSha256 && !/^[a-f0-9]{64}$/u.test(reviewedDeltaConfigSha256)) {
      throw new Error("--reviewed-source-config-sha256 must be a lowercase SHA-256");
    }
    const reviewedDeltaPlanSha256 = reviewedDeltaPlanHashValues[0]?.trim().toLowerCase();
    if (reviewedDeltaPlanSha256 && !/^[a-f0-9]{64}$/u.test(reviewedDeltaPlanSha256)) {
      throw new Error("--reviewed-source-delta-plan-sha256 must be a lowercase SHA-256");
    }
    const reviewedDeltaExecutionPlan = reviewedDeltaRequested
      ? loadTrustedHistoricalSourceDeltaExecutionPlan({
        path: resolve(reviewedDeltaPlanValues[0]!),
        trustRoot: dirname(resolve(reviewedDeltaPlanValues[0]!)),
        expectedSha256: reviewedDeltaPlanSha256!,
        allowedOwnerUids: currentUid === 0 ? [0] : [0, currentUid],
      }).value
      : undefined;
    if (reviewedDeltaExecutionPlan
      && reviewedDeltaExecutionPlan.configuration.sha256 !== reviewedDeltaConfigSha256) {
      throw new Error("Reviewed source-delta plan does not match the loaded configuration SHA-256");
    }
    const configuredDatabasePath = databasePath(args, environment);
    const attackKnowledgeKey = brainProjectionMode === "attack-knowledge-only"
      ? (args.flags.has("dry-run")
        ? createHash("sha256").update("ti-scale-attack-knowledge-disposable-preview-v1").digest()
        : configuredHazardKey(configuredDatabasePath, environment))
      : undefined;
    const boundedResume = args.flags.has("bounded-resume");
    const resumeMigrationId = args.values.get("resume")?.at(-1);
    if (boundedResume && (args.flags.has("dry-run") || !resumeMigrationId)) {
      throw new Error("--bounded-resume requires an executing --resume migration ID");
    }
    if (boundedResume && (brainProjectionMode !== "attack-knowledge-only" || !attackKnowledgeKey)) {
      throw new Error("--bounded-resume is available only for attack-knowledge-only extraction");
    }
    const executeMigration = () => new LegacyMigrationService({
      databasePath: configuredDatabasePath,
      sourceRoots: roots.map((root) => resolve(root)),
      engagementRoots: engagementRoots.map((root) => resolve(root)),
      historyRoots: historyRoots.map((root) => resolve(root)),
      outputDirectory: required(args, "output"),
      dryRun: args.flags.has("dry-run"),
      databaseBackupMode: "disabled",
      ...(settleSeconds !== undefined ? { settleSeconds } : {}),
      ...(explicitActiveSourceDeferrals.length > 0 ? { explicitActiveSourceDeferrals } : {}),
      ...(sqliteSnapshotQuarantineMappings.length > 0 ? {
        sqliteSnapshotQuarantineMappings,
        sqliteSnapshotQuarantineAcknowledged: true,
      } : {}),
      ...(reviewedDeltaExecutionPlan ? { reviewedDeltaExecutionPlan } : {}),
      sourceRetention,
      verifiedReferenceAcknowledged: args.flags.has("acknowledge-verified-reference"),
      brainProjectionMode,
      attackKnowledgeOnlyAcknowledged: args.flags.has("acknowledge-attack-knowledge-only"),
      ...(attackKnowledgeKey ? {
        attackKnowledgeManifestHandler: (manifest, database, context) => {
          const extractor = new HistoricalAttackKnowledgeExtractionService(database, {
            receiptHmacKey: attackKnowledgeKey,
          });
          const preview = context.dryRun ? new BoundedAttackKnowledgePreviewAccumulator() : undefined;
          let resumeAfterSourceKey: string | undefined;
          do {
            const extracted = extractor.extract(manifest, {
              dryRun: context.dryRun,
              ...(resumeAfterSourceKey ? { resumeAfterSourceKey } : {}),
            });
            preview?.add(extracted);
            context.recordBatch(extracted);
            resumeAfterSourceKey = extracted.nextResumeAfterSourceKey;
          } while (resumeAfterSourceKey);
          return preview ? [preview.finish()] : [];
        },
        genericAttackKnowledgeSourceHandler: (input, database, context) => {
          const allowed = new Set<string>(GENERIC_HISTORICAL_ATTACK_SOURCE_TYPES);
          const sources = input.sources.filter((source) => allowed.has(source.type));
          if (sources.length === 0) return [];
          const extractor = new GenericHistoricalAttackKnowledgeIngestionService(database, {
            receiptHmacKey: attackKnowledgeKey,
            maxSources: Math.max(10_000, sources.length),
          });
          const preview = context.dryRun ? new BoundedAttackKnowledgePreviewAccumulator() : undefined;
          const checkpoint = context.dryRun
            ? undefined
            : new MigrationMetadataRepository(database).latestExtractionCheckpoint(
              context.migrationId,
              "generic",
              input.inventoryReceiptHash,
            );
          if (checkpoint?.status === "completed") return [];
          let resumeAfterSourceKey = checkpoint?.nextResumeAfterSourceKey;
          let resumeAfterRecordKey = checkpoint?.nextResumeAfterRecordKey;
          let previousCursor = checkpoint?.status === "partial"
            ? JSON.stringify([
              checkpoint.nextResumeAfterSourceKey,
              checkpoint.nextResumeAfterRecordKey ?? null,
            ])
            : undefined;
          for (let page = 0; page < 100_000; page += 1) {
            const extracted = extractor.ingest({
              ...input,
              sources,
              dryRun: context.dryRun,
              ...(resumeAfterSourceKey ? { resumeAfterSourceKey } : {}),
              ...(resumeAfterRecordKey ? { resumeAfterRecordKey } : {}),
            });
            preview?.add(extracted);
            context.recordBatch(extracted);
            if (extracted.status === "completed") return preview ? [preview.finish()] : [];
            if (!extracted.nextResumeAfterSourceKey) {
              throw new Error("Generic historical ingestion returned partial without an opaque source cursor");
            }
            const cursor = JSON.stringify([
              extracted.nextResumeAfterSourceKey,
              extracted.nextResumeAfterRecordKey ?? null,
            ]);
            if (cursor === previousCursor) throw new Error("Generic historical ingestion returned a non-advancing cursor");
            previousCursor = cursor;
            resumeAfterSourceKey = extracted.nextResumeAfterSourceKey;
            resumeAfterRecordKey = extracted.nextResumeAfterRecordKey;
          }
          throw new Error("Generic historical ingestion exceeded its bounded resume-page limit");
        },
      } : {}),
      ...(resumeMigrationId ? { resumeMigrationId } : {}),
    }).run();
    let boundedResumeResult: BoundedHistoricalAttackKnowledgeResumeResult | undefined;
    const result = args.flags.has("dry-run")
      ? await executeMigration()
      : await (async () => {
          if (!existsSync(configuredDatabasePath)) {
            throw new Error("Canonical database does not exist; run db:migrate first");
          }
          const leaseDatabase = createDatabaseConnection({
            filename: configuredDatabasePath,
            fileMustExist: true,
            verifyIntegrity: false,
          });
          try {
            return await withCanonicalWriterLease(leaseDatabase, {
              ownerId: "operator:historical-migration",
              operation: "historical-engagement-import",
              ttlMs: 60 * 60_000,
            }, (handle, leases, heartbeat) => {
              leases.assertActive(handle);
              if (boundedResume) {
                boundedResumeResult = new BoundedHistoricalAttackKnowledgeResumeService(leaseDatabase, {
                  databasePath: configuredDatabasePath,
                  migrationId: resumeMigrationId!,
                  outputDirectory: required(args, "output"),
                  sourceRoots: [...roots, ...engagementRoots, ...historyRoots].map((root) => realpathSync(resolve(root))),
                  receiptHmacKey: attackKnowledgeKey!,
                  heartbeat: () => { heartbeat.renew(); },
                }).run();
              }
              return executeMigration();
            });
          } finally {
            leaseDatabase.close();
          }
        })();
    const attackKnowledge = result.report.attackKnowledgeExtraction
      ? args.flags.has("summary-output") ? (() => {
        const {
          sourceEvidenceCandidateIds,
          resumeCursors,
          ...summary
        } = result.report.attackKnowledgeExtraction;
        return {
          ...summary,
          sourceEvidenceCandidateCount: sourceEvidenceCandidateIds.length,
          resumeCursorCount: resumeCursors.length,
        };
      })() : result.report.attackKnowledgeExtraction
      : undefined;
    process.stdout.write(`${JSON.stringify({
      migrationId: result.migrationId,
      reportPath: result.reportPath,
      counts: result.report.counts,
      ...(result.report.settledSourceBoundary
        ? { settledSourceBoundary: result.report.settledSourceBoundary }
        : {}),
      ...(result.report.genericSourceDiscovery
        ? { genericSourceDiscovery: result.report.genericSourceDiscovery }
        : {}),
      ...(attackKnowledge ? { attackKnowledge } : {}),
      ...(boundedResumeResult ? { boundedResume: boundedResumeResult } : {}),
    }, null, 2)}\n`);
    return 0;
  }
  if (args.command === "verify") {
    const database = createDatabaseConnection({ filename: databasePath(args, environment), readonly: true, fileMustExist: true });
    try {
      const integrity = checkDatabaseIntegrity(database);
      const foreignKeys = database.pragma("foreign_key_check") as unknown[];
      process.stdout.write(`${JSON.stringify({ integrity, foreignKeyViolations: foreignKeys.length }, null, 2)}\n`);
      return integrity.ok && foreignKeys.length === 0 ? 0 : 2;
    } finally { database.close(); }
  }
  if (args.command === "reconcile") {
    const database = createDatabaseConnection({ filename: databasePath(args, environment), readonly: true, fileMustExist: true });
    try {
      const migrationId = args.values.get("migration-id")?.at(-1);
      if (!migrationId) throw new Error("--migration-id is required");
      const row = database.prepare(`
        SELECT report_json, report_hash FROM legacy_migration_reconciliation WHERE migration_id = ?
      `).get(migrationId) as { report_json: string; report_hash: string } | undefined;
      if (!row) throw new Error(`No reconciliation report exists for ${migrationId}`);
      process.stdout.write(`${JSON.stringify({ reportHash: row.report_hash, report: JSON.parse(row.report_json) }, null, 2)}\n`);
      return 0;
    } finally { database.close(); }
  }
  throw new Error(`Unknown command: ${args.command}`);
}

if (import.meta.main) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    process.stderr.write(`Migration failed: ${redactLegacyText(error instanceof Error ? error.message : String(error), 1_000)}\n`);
    process.exitCode = 1;
  });
}

export { main as runMigrationCli };
