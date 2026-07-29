import type { SqliteDatabase } from "../db";
import { canonicalJson } from "../missions/canonical";
import type { AutonomousPlanningSelection } from "../model-config";
import {
  ProviderAdvisoryPlanningError,
} from "./ProviderAdvisoryPlanningTypes";
import type {
  ProviderAdvisoryRuntimeOutcome,
  ProviderAdvisoryRuntimePort,
  ProviderAdvisoryRuntimeRequest,
} from "./ProviderAdvisoryRuntimePort";

const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$/u;

export interface LocalDeterministicPlanningPort<Input, Output> {
  readonly route: "local_deterministic";
  plan(input: Input, signal: AbortSignal): Promise<Output>;
}

export type SignedAutonomousPlanningRouteRequest<LocalInput> =
  | {
      readonly route: "local_deterministic";
      readonly missionId: string;
      readonly runId: string;
      readonly signedSelection: Extract<
        AutonomousPlanningSelection,
        { readonly route: "local_deterministic" }
      >;
      readonly localInput: LocalInput;
    }
  | {
      readonly route: "provider_advisory";
      readonly missionId: string;
      readonly runId: string;
      readonly signedSelection: Extract<
        AutonomousPlanningSelection,
        { readonly route: "provider_advisory" }
      >;
      readonly providerInput: Omit<
        ProviderAdvisoryRuntimeRequest,
        "missionId" | "runId" | "signedSelection"
      >;
    };

export type SignedAutonomousPlanningRouteOutcome<LocalOutput> =
  | {
      readonly status: "planned";
      readonly route: "local_deterministic";
      readonly result: LocalOutput;
    }
  | ProviderAdvisoryRuntimeOutcome;

interface ContractSelectionRow {
  readonly mission_id: string;
  readonly journey: string;
  readonly contract_state: string;
  readonly action_policy_json: string;
}

function fail(code: string, message: string): never {
  throw new ProviderAdvisoryPlanningError(
    code,
    message,
    "policy_drift",
    false,
  );
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactLocalSelection(
  value: AutonomousPlanningSelection,
): value is Extract<
  AutonomousPlanningSelection,
  { readonly route: "local_deterministic" }
> {
  if (!plainRecord(value)) return false;
  const expected = [
    "route",
    "plannerId",
    "enforcementMode",
    "disclosureClass",
    "executionAuthority",
  ].sort();
  const keys = Object.keys(value).sort();
  return (
    keys.length === expected.length
    && keys.every((key, index) => key === expected[index])
    && value.route === "local_deterministic"
    && value.plannerId ===
      "ti-scale.local-autonomous-contract-planner.v1"
    && value.enforcementMode === "local_policy"
    && value.disclosureClass === "local_only"
    && value.executionAuthority === "none"
  );
}

/**
 * Per-call route selector. It deliberately has no global provider boundary:
 * each invocation re-reads the confirmed contract and delegates only to the
 * exact signed local or provider-advisory route.
 */
export class SignedAutonomousPlanningRoutePort<LocalInput, LocalOutput> {
  constructor(private readonly options: {
    readonly database: SqliteDatabase;
    readonly local: LocalDeterministicPlanningPort<LocalInput, LocalOutput>;
    readonly provider: ProviderAdvisoryRuntimePort;
  }) {}

  async plan(
    input: SignedAutonomousPlanningRouteRequest<LocalInput>,
    signal: AbortSignal,
  ): Promise<SignedAutonomousPlanningRouteOutcome<LocalOutput>> {
    if (
      !OPAQUE_ID.test(input.missionId)
      || !OPAQUE_ID.test(input.runId)
    ) {
      fail(
        "autonomous_planning_route_identity_invalid",
        "The mission or run identity is not canonical.",
      );
    }
    if (input.route !== input.signedSelection.route) {
      fail(
        "autonomous_planning_route_discriminator_mismatch",
        "The requested planning route does not match its supplied signed selection.",
      );
    }
    this.assertConfirmedSelection(
      input.missionId,
      input.runId,
      input.signedSelection,
    );
    if (input.route === "local_deterministic") {
      if (!exactLocalSelection(input.signedSelection)) {
        fail(
          "autonomous_local_planning_selection_invalid",
          "The supplied local planning selection is not exact.",
        );
      }
      const result = await this.options.local.plan(
        input.localInput,
        signal,
      );
      return Object.freeze({
        status: "planned",
        route: "local_deterministic",
        result,
      });
    }
    return this.options.provider.plan({
      ...input.providerInput,
      missionId: input.missionId,
      runId: input.runId,
      signedSelection: input.signedSelection,
    }, signal);
  }

  private assertConfirmedSelection(
    missionId: string,
    runId: string,
    selection: AutonomousPlanningSelection,
  ): void {
    const row = this.options.database.prepare(`
      SELECT
        run.mission_id,
        run.journey,
        contract.state AS contract_state,
        contract.action_policy_json
      FROM runs AS run
      JOIN mission_contracts AS contract ON contract.id = run.contract_id
      WHERE run.id = ?
    `).get(runId) as ContractSelectionRow | undefined;
    if (
      !row
      || row.mission_id !== missionId
      || row.journey !== "autonomous"
      || row.contract_state !== "confirmed"
    ) {
      fail(
        "autonomous_planning_route_contract_mismatch",
        "The selected planning route is not attached to one confirmed Autonomous run contract.",
      );
    }
    let actionPolicy: unknown;
    try {
      actionPolicy = JSON.parse(row.action_policy_json) as unknown;
    } catch {
      fail(
        "autonomous_planning_route_contract_invalid",
        "The confirmed action policy is not valid JSON.",
      );
    }
    const contractSelection = plainRecord(actionPolicy)
      ? actionPolicy.planningSelection
      : undefined;
    if (
      !contractSelection
      || canonicalJson(contractSelection) !== canonicalJson(selection)
    ) {
      fail(
        "autonomous_planning_route_selection_mismatch",
        "The supplied planning selection does not exactly match the confirmed contract.",
      );
    }
  }
}
