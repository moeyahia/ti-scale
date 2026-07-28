import { createHash } from "node:crypto";
import { CommandRuntimeError } from "../command-runtime/types";
import type { Journey, RunState } from "../supervisor";

const RUN_STATES = new Set<RunState>([
  "queued",
  "planning",
  "awaiting_contract_confirmation",
  "running",
  "waiting_guided_decision",
  "blocked",
  "recovering",
  "completed",
  "failed",
  "cancelled",
]);
const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,239}$/u;
const CURSOR_VERSION = 1 as const;

export type RuntimeRunView = "operational";

export interface RuntimeRunCursor {
  readonly updatedAt: string;
  readonly id: string;
}

export interface ParsedRuntimeRunQuery {
  readonly query?: string;
  readonly journey?: Journey;
  readonly status?: RunState;
  readonly view?: RuntimeRunView;
  readonly statuses?: readonly RunState[];
  readonly limit: number;
  readonly cursor?: RuntimeRunCursor;
  readonly filterHash: string;
}

interface EncodedRuntimeRunCursor {
  readonly version: typeof CURSOR_VERSION;
  readonly updatedAt: string;
  readonly id: string;
  readonly filterHash: string;
}

function invalid(code: string, message: string): CommandRuntimeError {
  return new CommandRuntimeError(400, code, message, {
    humanMessage: message,
    category: "invalid_input",
    remediation: "Use the documented run filters and restart pagination from the first page.",
  });
}

function optionalText(value: unknown, field: string, maximum: number): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw invalid(`invalid_${field}`, `${field} must be supplied once.`);
  const normalized = value.trim().normalize("NFKC");
  if (!normalized || normalized.length > maximum || /[\u0000-\u001F\u007F]/u.test(normalized)) {
    throw invalid(`invalid_${field}`, `${field} is invalid.`);
  }
  return normalized;
}

function boundedLimit(value: unknown): number {
  if (value === undefined) return 50;
  if (typeof value !== "string" || !/^(?:[1-9]|[1-9][0-9]|100)$/u.test(value)) {
    throw invalid("invalid_pagination", "limit must be an integer from 1 through 100.");
  }
  return Number(value);
}

function filterHash(input: {
  readonly journey?: Journey;
  readonly status?: RunState;
  readonly view?: RuntimeRunView;
  readonly query?: string;
}): string {
  return createHash("sha256").update(JSON.stringify({
    journey: input.journey ?? null,
    status: input.status ?? null,
    view: input.view ?? null,
    query: input.query ?? null,
  }), "utf8").digest("hex");
}

function operationalStates(journey: Journey): readonly RunState[] {
  return journey === "autonomous"
    ? ["queued", "planning", "awaiting_contract_confirmation", "running", "blocked", "recovering"]
    : ["queued", "planning", "running", "waiting_guided_decision", "blocked", "recovering"];
}

function decodeCursor(value: string, expectedFilterHash: string): RuntimeRunCursor {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Partial<EncodedRuntimeRunCursor>;
    const canonicalUpdatedAt = typeof parsed.updatedAt === "string"
      && Number.isFinite(Date.parse(parsed.updatedAt))
      ? new Date(parsed.updatedAt).toISOString()
      : null;
    if (
      parsed.version !== CURSOR_VERSION
      || typeof parsed.updatedAt !== "string"
      || canonicalUpdatedAt !== parsed.updatedAt
      || typeof parsed.id !== "string"
      || !RESOURCE_ID.test(parsed.id)
      || parsed.filterHash !== expectedFilterHash
    ) throw new Error("cursor boundary mismatch");
    return { updatedAt: parsed.updatedAt, id: parsed.id };
  } catch {
    throw invalid(
      "invalid_pagination",
      "The run page cursor is invalid or belongs to different filters.",
    );
  }
}

/**
 * Parse the public V2 run-list query once so read-only and executable runtime
 * compositions cannot drift. Operational views require an explicit journey;
 * that keeps Autonomous user-wait states out of the Live projection by design.
 */
export function parseRuntimeRunQuery(queryInput: Record<string, unknown>): ParsedRuntimeRunQuery {
  const allowed = new Set(["query", "journey", "status", "view", "limit", "cursor"]);
  const unsupported = Object.keys(queryInput).find((key) => !allowed.has(key));
  if (unsupported) throw invalid("unsupported_runtime_filter", `Unsupported runtime filter: ${unsupported}.`);

  const journeyValue = optionalText(queryInput.journey, "journey", 10);
  const journey = journeyValue === undefined
    ? undefined
    : journeyValue === "autonomous" || journeyValue === "guided"
      ? journeyValue
      : (() => { throw invalid("invalid_journey_filter", "journey must be autonomous or guided."); })();
  const statusValue = optionalText(queryInput.status, "run_status", 40);
  if (statusValue !== undefined && !RUN_STATES.has(statusValue as RunState)) {
    throw invalid("invalid_run_status", "status is not a canonical run state.");
  }
  const status = statusValue as RunState | undefined;
  const viewValue = optionalText(queryInput.view, "run_view", 40);
  if (viewValue !== undefined && viewValue !== "operational") {
    throw invalid("invalid_run_view", "view must be operational when supplied.");
  }
  const view = viewValue as RuntimeRunView | undefined;
  if (view && !journey) {
    throw invalid("invalid_run_view", "The operational run view requires an explicit journey.");
  }
  if (view && status) {
    throw invalid("ambiguous_run_state_filter", "Choose either the operational run view or one exact status, not both.");
  }
  const search = optionalText(queryInput.query, "run_search", 300);
  const hash = filterHash({ journey, status, view, query: search });
  const cursorValue = optionalText(queryInput.cursor, "pagination", 2_048);
  return {
    ...(search ? { query: search } : {}),
    ...(journey ? { journey } : {}),
    ...(status ? { status } : {}),
    ...(view ? { view, statuses: operationalStates(journey!) } : {}),
    limit: boundedLimit(queryInput.limit),
    ...(cursorValue ? { cursor: decodeCursor(cursorValue, hash) } : {}),
    filterHash: hash,
  };
}

export function encodeRuntimeRunCursor(
  cursor: RuntimeRunCursor,
  currentFilterHash: string,
): string {
  const payload: EncodedRuntimeRunCursor = {
    version: CURSOR_VERSION,
    updatedAt: cursor.updatedAt,
    id: cursor.id,
    filterHash: currentFilterHash,
  };
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}
