import type { SqliteDatabase } from "../db";

function stringArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) =>
    typeof item !== "string" || !item.trim())) {
    throw new TypeError(`${label} is malformed`);
  }
  return Object.freeze([...new Set(value)]);
}

function parsedObject(value: string, label: string): Readonly<Record<string, unknown>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new TypeError(`${label} is malformed`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError(`${label} is malformed`);
  }
  return parsed as Readonly<Record<string, unknown>>;
}

/**
 * Resolves the only memory policy an active Autonomous run may consume.
 *
 * Mission projection data is intentionally excluded: the confirmed contract
 * revision bound to the run owns scope classes and exact node IDs. An
 * immutable follow-up selection may further narrow that policy to its reviewed
 * verified lessons.
 */
export function resolveAutonomousRunMemoryPolicy(input: Readonly<{
  database: SqliteDatabase;
  missionId: string;
  runId: string;
}>): Readonly<{
  allowedScopes: readonly string[];
  exactContextNodeIds: readonly string[];
}> {
  const row = input.database.prepare(`
    SELECT run.mission_id, run.journey, run.contract_version_bound,
      run.contract_hash_bound, contract.version, contract.contract_hash,
      contract.state, contract.memory_scopes_json, contract.action_policy_json
    FROM runs run
    JOIN mission_contracts contract
      ON contract.id = run.contract_id AND contract.mission_id = run.mission_id
    WHERE run.id = ? AND run.mission_id = ?
  `).get(input.runId, input.missionId) as {
    readonly mission_id: string;
    readonly journey: "autonomous" | "guided";
    readonly contract_version_bound: number | null;
    readonly contract_hash_bound: string | null;
    readonly version: number;
    readonly contract_hash: string;
    readonly state: string;
    readonly memory_scopes_json: string;
    readonly action_policy_json: string;
  } | undefined;
  if (
    !row
    || row.journey !== "autonomous"
    || row.state !== "confirmed"
    || row.contract_version_bound !== row.version
    || row.contract_hash_bound !== row.contract_hash
  ) {
    throw new TypeError(
      "Autonomous run memory policy is not bound to its unchanged confirmed contract",
    );
  }

  let parsedScopes: unknown;
  try {
    parsedScopes = JSON.parse(row.memory_scopes_json) as unknown;
  } catch {
    throw new TypeError("Autonomous contract memory scopes are malformed");
  }
  const allowedScopes = stringArray(
    parsedScopes,
    "Autonomous contract memory scopes",
  );
  const actionPolicy = parsedObject(
    row.action_policy_json,
    "Autonomous contract action policy",
  );
  const contractNodeIds = stringArray(
    actionPolicy.contextNodeIds,
    "Autonomous contract exact memory selection",
  );
  const selections = input.database.prepare(`
    SELECT node_id, selection_type FROM run_context_selections
    WHERE run_id = ? ORDER BY selected_at, id
  `).all(input.runId) as Array<{
    readonly node_id: string;
    readonly selection_type: "verified_lesson";
  }>;
  if (selections.some(({ selection_type }) =>
    selection_type !== "verified_lesson")) {
    throw new TypeError(
      "Autonomous run context contains an unsupported immutable selection type",
    );
  }
  if (selections.length > 0 && !allowedScopes.includes("verified_lessons")) {
    throw new TypeError(
      "Autonomous contract does not permit the selected verified-lesson context",
    );
  }

  return Object.freeze({
    allowedScopes,
    exactContextNodeIds: Object.freeze(
      selections.length > 0
        ? [...new Set(selections.map(({ node_id }) => node_id))]
        : [...contractNodeIds],
    ),
  });
}
