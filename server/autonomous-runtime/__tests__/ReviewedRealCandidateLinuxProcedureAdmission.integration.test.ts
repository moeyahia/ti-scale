import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  createDatabaseConnection,
  migrateDatabase,
} from "../../db";
import {
  HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider,
} from "../ReviewedRealCandidateLinuxProcedureAdapter";
import {
  REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
  REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
  parseReviewedRealCandidateLinuxProfile,
  reviewedRealCandidateLinuxOperations,
} from "../ReviewedRealCandidateLinuxTransport";
import {
  exactCandidateLinuxTargetScope,
} from "../CandidateLinuxTargetScope";

const NOW = new Date("2026-07-28T20:00:00.000Z");
const BINDING_ID = "binding.provider-admission-contract";
const SOURCE_SPEC_ID = "spec.provider-admission-source";
const SOURCE_SCRIPT_ID = "script.provider-admission-exploit";
const SOURCE_OBSERVER_ID = "observer.provider-admission-exploit";
const TARGET_SCOPE = exactCandidateLinuxTargetScope("10.129.10.20");
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function digestBytes(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function providerSource(logPath: string): string {
  return `#!/usr/bin/env bun
import { createHash } from "node:crypto";
import { appendFileSync } from "node:fs";

const OPERATIONS = ${JSON.stringify(reviewedRealCandidateLinuxOperations())};
const BOUNDARY = ${JSON.stringify({
  typedOperationsOnly: true,
  genericCommand: false,
  shell: false,
  argv: false,
  payload: false,
  credentialsFromRuntime: false,
  exactTargetFromCanonicalAction: true,
  succeededAttackAttemptRequired: true,
  derivedCurrentRunSpecOnly: true,
  publicProvider: false,
  hashOnlyFlagProofs: true,
})};
const LOG_PATH = ${JSON.stringify(logPath)};
const NOW = ${JSON.stringify(NOW.toISOString())};
const encode = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(encode).join(",") + "]";
  return "{" + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ":" + encode(value[key])).join(",") + "}";
};
const digest = (value) =>
  createHash("sha256").update(encode(value), "utf8").digest("hex");
const success = (result) =>
  process.stdout.write(JSON.stringify({ ok: true, result }) + "\\n");
const input = JSON.parse((await Bun.stdin.text()).trim());
appendFileSync(LOG_PATH, JSON.stringify(input) + "\\n", { mode: 0o600 });
if (input.operation === "attest") {
  const unsigned = {
    schemaVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure-attestation.v1",
    protocolVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure.v1",
    profileSha256: input.profileSha256,
    procedureExecutableSha256: input.procedureExecutableSha256,
    bindingId: input.bindingId,
    postExploitSpecId: input.postExploitSpecId,
    scriptArtifactId: input.scriptArtifactId,
    exploitOutcomeObserverSpecId: input.exploitOutcomeObserverSpecId,
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: input.targetScope,
    operations: OPERATIONS,
    boundary: BOUNDARY,
    observedAt: NOW,
    expiresAt: new Date(Date.parse(NOW) + 60_000).toISOString(),
  };
  success({ ...unsigned, receiptSha256: digest(unsigned) });
} else if (input.operation === "conformance") {
  const unsigned = {
    schemaVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure-conformance.v1",
    protocolVersion:
      "ti-scale.reviewed-real-candidate-linux-procedure.v1",
    profileSha256: input.profileSha256,
    procedureExecutableSha256: input.procedureExecutableSha256,
    bindingId: input.bindingId,
    postExploitSpecId: input.postExploitSpecId,
    scriptArtifactId: input.scriptArtifactId,
    exploitOutcomeObserverSpecId: input.exploitOutcomeObserverSpecId,
    targetScope: input.targetScope,
    cases: [
      { operation: "open", result: { accepted: true } },
      {
        operation: "observe_identity",
        result: {
          principal: "operator",
          uid: 1000,
          gid: 1000,
          groups: ["operator"],
        },
      },
      {
        operation: "prove_user_flag_hash",
        result: { sha256: "a".repeat(64), byteSize: 32 },
      },
      { operation: "close", result: { closed: true } },
      {
        operation: "privilege_escalation",
        result: { accepted: true },
      },
      {
        operation: "observe_root_identity",
        result: {
          principal: "root",
          uid: 0,
          gid: 0,
          groups: ["root"],
        },
      },
      {
        operation: "prove_root_flag_hash",
        result: { sha256: "b".repeat(64), byteSize: 32 },
      },
      { operation: "cleanup", result: { closed: true } },
    ],
  };
  success({ ...unsigned, receiptSha256: digest(unsigned) });
} else {
  process.stdout.write(JSON.stringify({
    ok: false,
    error: {
      code: "unexpected_target_contact",
      message: "Admission must not invoke a represented target operation",
    },
  }) + "\\n");
  process.exitCode = 1;
}
`;
}

function fixture(input: Readonly<{
  providerSource?: string;
  pinnedProcedurePath?: string;
  pinnedProcedureSha256?: string;
}> = {}) {
  const root = mkdtempSync(join(
    tmpdir(),
    "ti-scale-provider-admission-contract-",
  ));
  roots.push(root);
  chmodSync(root, 0o700);
  const adapterPath = join(root, "adapter");
  const procedurePath = join(root, "provider");
  const logPath = join(root, "provider-requests.jsonl");
  writeFileSync(
    adapterPath,
    "#!/usr/bin/env bun\n// adapter identity only\n",
    { mode: 0o500 },
  );
  writeFileSync(
    procedurePath,
    input.providerSource ?? providerSource(logPath),
    { mode: 0o500 },
  );
  const procedureSha256 = digestBytes(procedurePath);
  const profile = parseReviewedRealCandidateLinuxProfile({
    schemaVersion: REVIEWED_REAL_CANDIDATE_LINUX_PROFILE_SCHEMA_VERSION,
    profileId: "profile.provider-admission-contract",
    candidateClass: "reviewed_real_candidate_v1",
    realTargetSupport: true,
    targetScope: TARGET_SCOPE,
    bindingId: BINDING_ID,
    postExploitSpec: {
      id: SOURCE_SPEC_ID,
      expectedSha256: "d".repeat(64),
      exploitOutcomeObserverSpecId: SOURCE_OBSERVER_ID,
      scriptArtifactId: SOURCE_SCRIPT_ID,
      expectedPrincipal: "operator",
      expectedUid: 1_000,
      declaredUserFlagPath: "/home/operator/user.txt",
      declaredRootFlagPath: "/root/root.txt",
    },
    adapter: {
      executablePath: adapterPath,
      executableSha256: digestBytes(adapterPath),
      socketPath: join(root, "adapter.sock"),
      socketGid: process.getgid?.() ?? 0,
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_ADAPTER_PROTOCOL_VERSION,
    },
    procedure: {
      executablePath:
        input.pinnedProcedurePath ?? procedurePath,
      executableSha256:
        input.pinnedProcedureSha256 ?? procedureSha256,
      protocolVersion:
        REVIEWED_REAL_CANDIDATE_LINUX_PROCEDURE_PROTOCOL_VERSION,
    },
    boundary: {
      typedOperationsOnly: true,
      genericCommand: false,
      shell: false,
      argv: false,
      payload: false,
      credentialsFromRuntime: false,
      exactTargetFromCanonicalAction: true,
      succeededAttackAttemptRequired: true,
      derivedCurrentRunSpecOnly: true,
      publicProvider: false,
      hashOnlyFlagProofs: true,
    },
    operations: reviewedRealCandidateLinuxOperations(),
  });
  return Object.freeze({
    root,
    logPath,
    procedurePath,
    procedureSha256,
    profile,
  });
}

function provider(
  value: ReturnType<typeof fixture>,
): HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider {
  return new HashPinnedStdioReviewedRealCandidateLinuxProcedureProvider({
    profile: value.profile,
    profileSha256: "c".repeat(64),
    procedureExecutablePath: value.procedurePath,
    procedureExecutableSha256: value.procedureSha256,
    allowedOwnerUids: [process.getuid?.() ?? 0],
    now: () => NOW,
  });
}

describe("reviewed procedure-provider pre-plan contract", () => {
  test("rejects an ordinary exploit-only executable that does not implement the target-free provider protocol", async () => {
    const value = fixture({
      providerSource: [
        "#!/usr/bin/env python3",
        "import argparse",
        "parser = argparse.ArgumentParser()",
        "parser.add_argument('--target', required=True)",
        "parser.parse_args()",
        "",
      ].join("\n"),
    });
    await expect(
      provider(value).attest(new AbortController().signal),
    ).rejects.toThrow("Reviewed candidate procedure failed");
  });

  test("rejects a procedure executable whose exact path or bytes differ from the profile pin", () => {
    const value = fixture({
      pinnedProcedureSha256: "f".repeat(64),
    });
    expect(() => provider(value)).toThrow(
      "differs from the executable and protocol pinned by the reviewed profile",
    );
  });

  test("attests and validates all eight ordered result schemas without an invoke request or target", async () => {
    const value = fixture();
    const implementation = provider(value);
    const attestation = await implementation.attest(
      new AbortController().signal,
    );
    const conformance = await implementation.conform(
      new AbortController().signal,
    );

    expect(attestation).toMatchObject({
      procedureExecutableSha256: value.procedureSha256,
      scriptArtifactId: SOURCE_SCRIPT_ID,
      operations: reviewedRealCandidateLinuxOperations(),
    });
    expect(value.procedureSha256).not.toBe(
      value.profile.postExploitSpec.expectedSha256,
    );
    expect(conformance).toMatchObject({
      procedureExecutableSha256: value.procedureSha256,
      scriptArtifactId: SOURCE_SCRIPT_ID,
    });
    expect(conformance.cases.map(({ operation }) => operation)).toEqual(
      [...reviewedRealCandidateLinuxOperations()],
    );
    expect(conformance.receiptSha256).toMatch(/^[a-f0-9]{64}$/u);

    const requests = readFileSync(value.logPath, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(requests.map(({ operation }) => operation)).toEqual([
      "attest",
      "conformance",
    ]);
    for (const request of requests) {
      expect(request).not.toHaveProperty("request");
      expect(request).not.toHaveProperty("target");
      expect(request.targetScope).toEqual(TARGET_SCOPE);
      const { targetScope: _declaredProviderScope, ...targetFreeEnvelope } =
        request;
      expect(JSON.stringify(targetFreeEnvelope)).not.toContain("10.");
    }
  });

  test("keeps the admission binding immutable after an activation is inserted", () => {
    const root = mkdtempSync(join(
      tmpdir(),
      "ti-scale-provider-admission-schema-",
    ));
    roots.push(root);
    const database = createDatabaseConnection({
      filename: join(root, "ti-scale.sqlite"),
    });
    try {
      migrateDatabase(database);

      // This fixture isolates the UPDATE contract. The two INSERT lineage
      // triggers are separately covered by service-level activation tests.
      database.exec("PRAGMA foreign_keys = OFF");
      database.exec(
        "DROP TRIGGER trg_reviewed_candidate_procedure_activation_lineage_insert",
      );
      database.exec(
        "DROP TRIGGER IF EXISTS trg_reviewed_candidate_procedure_activation_admission_insert",
      );
      database.prepare(`
        INSERT INTO reviewed_candidate_linux_procedure_activations (
          id, mission_id, run_id, plan_id, step_id, attack_attempt_id,
          target_node_id, exact_target, source_post_exploit_spec_id,
          post_exploit_spec_id, script_artifact_id, script_content_hash,
          exploit_outcome_observer_spec_id,
          exploit_outcome_observer_spec_hash,
          script_validation_artifact_id,
          script_validation_artifact_hash,
          represented_action_binding_hash, profile_id, profile_sha256,
          transport_binding_id, procedure_executable_path,
          procedure_executable_sha256, idempotency_key_hash, status,
          activation_receipt_json, activation_receipt_hash, activated_by,
          activated_at, procedure_admission_id
        ) VALUES (
          'activation.immutable-admission', 'mission.fixture', 'run.fixture',
          'plan.fixture', 'step.fixture', 'attempt.fixture', 'target.fixture',
          '10.0.0.7', 'spec.source.fixture', 'spec.derived.fixture',
          'script.fixture', ?, 'observer.fixture', ?, 'artifact.fixture', ?,
          ?, 'profile.fixture', ?, 'binding.fixture', '/opt/provider', ?, ?,
          'active', '{}', ?, 'system:test', ?, 'admission.original'
        )
      `).run(
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64),
        "4".repeat(64),
        "5".repeat(64),
        "6".repeat(64),
        "7".repeat(64),
        "8".repeat(64),
        NOW.toISOString(),
      );

      const update = database.prepare(`
        UPDATE reviewed_candidate_linux_procedure_activations
        SET procedure_admission_id = ?
        WHERE id = 'activation.immutable-admission'
      `);
      expect(() => update.run("admission.rebound")).toThrow(
        "reviewed candidate procedure activation admission is immutable",
      );
      expect(() => update.run(null)).toThrow(
        "reviewed candidate procedure activation admission is immutable",
      );
      expect(database.prepare(`
        SELECT procedure_admission_id
        FROM reviewed_candidate_linux_procedure_activations
        WHERE id = 'activation.immutable-admission'
      `).get()).toEqual({
        procedure_admission_id: "admission.original",
      });
    } finally {
      database.close();
    }
  });
});
