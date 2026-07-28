import { StatusPill } from "../../design-system/components/Primitives";
import type {
  AutonomousMissionPreflight,
  ReadinessCheck,
} from "../../domain/types/commandOs";
import type { RuntimeReadinessSnapshot } from "../../domain/types/runtimeReadiness";

export type AutonomousReadinessCategoryId =
  | "execution_boundary"
  | "provider"
  | "specialist"
  | "tools_mcp"
  | "budgets"
  | "scope_evidence_memory"
  | "platform";

export interface AutonomousReadinessCategory {
  readonly id: AutonomousReadinessCategoryId;
  readonly title: string;
  readonly explanation: string;
  readonly checks: readonly ReadinessCheck[];
}

const CATEGORY_COPY: Readonly<Record<AutonomousReadinessCategoryId, Omit<AutonomousReadinessCategory, "checks">>> = {
  execution_boundary: {
    id: "execution_boundary",
    title: "Execution boundary",
    explanation: "The unattended control chain needs a mounted planner, evaluator, action gate, recovery path, and cancellation boundary.",
  },
  provider: {
    id: "provider",
    title: "Provider enforcement",
    explanation: "At least one authenticated model route must execute behind Ti-Scale's local Autonomous policy boundary.",
  },
  specialist: {
    id: "specialist",
    title: "Specialist assignment",
    explanation: "The reviewed contract must bind work to a compatible specialist with a current execution route.",
  },
  tools_mcp: {
    id: "tools_mcp",
    title: "Tools, MCP, and evidence producers",
    explanation: "Every required action and evidence type needs an exact, runnable tool binding inside the Autonomous boundary.",
  },
  budgets: {
    id: "budgets",
    title: "Budgets and accounting",
    explanation: "Finite token, cost, time, and storage limits need authoritative measurements before unattended execution can start.",
  },
  scope_evidence_memory: {
    id: "scope_evidence_memory",
    title: "Scope, evidence, and memory",
    explanation: "Authorization, contract integrity, evidence rules, and selected Second Brain context must remain valid for this exact mission.",
  },
  platform: {
    id: "platform",
    title: "Platform services",
    explanation: "The canonical database, authentication, and durable event path must be healthy enough to preserve the run safely.",
  },
};

const CATEGORY_ORDER: readonly AutonomousReadinessCategoryId[] = [
  "execution_boundary",
  "provider",
  "specialist",
  "tools_mcp",
  "budgets",
  "scope_evidence_memory",
  "platform",
];

function categoryId(checkId: string): AutonomousReadinessCategoryId {
  const id = checkId.toLocaleLowerCase("en-US");
  if (id.includes("token_accounting") || id.includes("cost_accounting") || id.includes("budget")) {
    return "budgets";
  }
  if (id.includes("execution_boundary") || id === "contract_action_boundary" || id === "contract_controls" || id === "legacy_execution_surface") {
    return "execution_boundary";
  }
  if (id.includes("provider")) return "provider";
  if (id.includes("specialist") || id.includes("agent_fleet")) return "specialist";
  if (id.includes("mcp") || id.includes("tool") || id === "contract_evidence_capability") return "tools_mcp";
  if (id === "database" || id.includes("authentication") || id === "event_stream") return "platform";
  return "scope_evidence_memory";
}

export function autonomousReadinessChecks(checks: readonly ReadinessCheck[]): readonly ReadinessCheck[] {
  return checks.filter((check) => check.journeys.includes("autonomous"));
}

export function groupAutonomousReadinessBlockers(
  checks: readonly ReadinessCheck[],
): readonly AutonomousReadinessCategory[] {
  const grouped = new Map<AutonomousReadinessCategoryId, ReadinessCheck[]>();
  for (const check of autonomousReadinessChecks(checks)) {
    if (check.status !== "fail") continue;
    const id = categoryId(check.id);
    const items = grouped.get(id) ?? [];
    items.push(check);
    grouped.set(id, items);
  }
  return CATEGORY_ORDER.flatMap((id) => {
    const categoryChecks = grouped.get(id);
    return categoryChecks?.length
      ? [{ ...CATEGORY_COPY[id], checks: categoryChecks }]
      : [];
  });
}

function ReadinessCheckItem({ check }: { readonly check: ReadinessCheck }) {
  return <li>
    <StatusPill status={check.status} />
    <span>
      <strong>{check.label}</strong>
      <small>{check.impact}</small>
      {check.remediation && check.status !== "pass" && <small><b>How to resolve:</b> {check.remediation}</small>}
    </span>
  </li>;
}

function GuidedLocalToolComparison({
  runtime,
  pending,
}: {
  readonly runtime?: RuntimeReadinessSnapshot;
  readonly pending?: boolean;
}) {
  const guidedToolsReady = runtime?.execution.guidedToolExecution === "ready";
  const guidedManualReady = runtime?.execution.guided === "manual_only";
  const status = pending ? "checking" : guidedToolsReady ? "ready" : guidedManualReady ? "manual_only" : "unavailable";
  const title = pending
    ? "Checking Guided local tools"
    : guidedToolsReady
      ? "Guided local tools are available"
      : guidedManualReady
        ? "Guided manual steps are available"
        : "Guided local tool execution is unavailable";
  const description = pending
    ? "Ti-Scale is reading the current process-level runtime attestation."
    : guidedToolsReady
      ? "A Guided mission may run one reviewed local specialist action after you approve its exact target and parameters. This does not provide unattended planning or Autonomous execution."
      : guidedManualReady
        ? "Ti-Scale can represent and record operator-run Guided steps, but it cannot dispatch a local tool from this runtime."
        : runtime
          ? "The current process has not attested an exact-step Guided local tool path."
          : "Guided local tool status could not be verified in this review.";
  return <article>
    <div><p className="os-eyebrow">Different journey</p><h4>{title}</h4></div>
    <StatusPill status={status} />
    <p>{description}</p>
  </article>;
}

export function AutonomousReadinessReview({
  preflight,
  runtime,
  runtimePending = false,
  preflightRefreshing = false,
  preflightRefreshFailed = false,
}: {
  readonly preflight: AutonomousMissionPreflight;
  readonly runtime?: RuntimeReadinessSnapshot;
  readonly runtimePending?: boolean;
  /** The stamped runtime capability state changed after this review. */
  readonly preflightRefreshing?: boolean;
  /** The old review remains retired when its automatic replacement fails. */
  readonly preflightRefreshFailed?: boolean;
}) {
  if (preflightRefreshing || preflightRefreshFailed) {
    return <section
      className="os-autonomous-readiness"
      aria-labelledby="autonomous-readiness-title"
      aria-live="polite"
      data-readiness-review-state={preflightRefreshFailed ? "refresh-failed" : "refreshing"}
    >
      <div className="os-readiness-summary os-readiness-summary--journey">
        <span aria-hidden="true"><strong>—</strong>/100</span>
        <div>
          <p className="os-eyebrow">Selected journey · Autonomous</p>
          <h3 id="autonomous-readiness-title">
            {preflightRefreshFailed ? "Autonomous readiness needs a new review" : "Refreshing Autonomous readiness"}
          </h3>
          <p>{preflightRefreshFailed
            ? "Runtime capability state changed and the replacement review could not be completed. The previous score and blockers are retired. Return to the previous step and continue to run a new server review."
            : "Runtime capability state changed after the previous review. Ti-Scale retired the old score and blockers and is checking this exact contract again."}</p>
        </div>
        <StatusPill status={preflightRefreshFailed ? "blocked" : "checking"}>
          {preflightRefreshFailed ? "Review required" : "Rechecking"}
        </StatusPill>
      </div>
    </section>;
  }

  const checks = autonomousReadinessChecks(preflight.readiness.checks);
  const blockers = checks.filter((check) => check.status === "fail");
  const warnings = checks.filter((check) => check.status === "warn");
  const passed = checks.filter((check) => check.status === "pass");
  const categories = groupAutonomousReadinessBlockers(checks);
  const blocked = blockers.length > 0;

  return <section className="os-autonomous-readiness" aria-labelledby="autonomous-readiness-title">
    <div className="os-readiness-summary os-readiness-summary--journey">
      <span aria-label={`Autonomous readiness score ${preflight.readiness.score} out of 100`}><strong>{preflight.readiness.score}</strong>/100</span>
      <div>
        <p className="os-eyebrow">Selected journey · Autonomous</p>
        <h3 id="autonomous-readiness-title">{blocked ? "Autonomous launch is blocked" : preflight.readiness.status === "degraded" ? "Autonomous launch is degraded" : "Autonomous launch is ready"}</h3>
        <p>{blocked
          ? `${blockers.length} failing check${blockers.length === 1 ? " prevents" : "s prevent"} unattended execution. Passing local or Guided capabilities do not override these Autonomous requirements.`
          : `${warnings.length} advisory check${warnings.length === 1 ? " remains" : "s remain"}; no Autonomous launch blocker is reported.`}</p>
      </div>
      <StatusPill status={preflight.readiness.status}>{blocked ? "Launch blocked" : preflight.readiness.status}</StatusPill>
    </div>

    <div className="os-journey-boundary-comparison" aria-label="Autonomous and Guided execution boundary comparison">
      <article>
        <div><p className="os-eyebrow">Selected journey</p><h4>Autonomous unattended execution</h4></div>
        <StatusPill status={blocked ? "blocked" : preflight.readiness.status} />
        <p>{blocked
          ? "Unavailable for this contract until every failing Autonomous check below is resolved and preflight is run again."
          : "The reviewed contract currently satisfies its Autonomous launch gate."}</p>
      </article>
      <GuidedLocalToolComparison runtime={runtime} pending={runtimePending} />
    </div>

    {blocked ? <div className="os-readiness-blocker-groups">
      <header><p className="os-eyebrow">What must change</p><h3>Autonomous launch blockers by system layer</h3><p>Resolve the checks that apply to the required execution chain; changing to Guided is a separate operator choice, not a way to relabel this mission as Autonomous.</p></header>
      {categories.map((category) => <section key={category.id} aria-labelledby={`autonomous-readiness-${category.id}`}>
        <div className="os-readiness-category-heading">
          <div><h4 id={`autonomous-readiness-${category.id}`}>{category.title}</h4><p>{category.explanation}</p></div>
          <span>{category.checks.length} blocker{category.checks.length === 1 ? "" : "s"}</span>
        </div>
        <ul className="os-review-list">{category.checks.map((check) => <ReadinessCheckItem key={check.id} check={check} />)}</ul>
      </section>)}
    </div> : null}

    <details className="os-readiness-other-checks">
      <summary>{passed.length} passed · {warnings.length} advisory</summary>
      <div><p>These checks remain visible for audit. A pass here does not cancel a failure in another Autonomous system layer.</p><ul className="os-review-list">{checks.filter((check) => check.status !== "fail").map((check) => <ReadinessCheckItem key={check.id} check={check} />)}</ul></div>
    </details>

    <dl className="os-review-grid">
      <div><dt>Contract version</dt><dd>{preflight.contract.version}</dd></div>
      <div><dt>Contract SHA-256</dt><dd className="os-mono">{preflight.contract.hash}</dd></div>
      <div><dt>Compatible Autonomous providers</dt><dd>{preflight.execution.providers.filter((provider) => provider.compatible).length}</dd></div>
      <div><dt>Signed Autonomous specialists</dt><dd>{preflight.execution.team.effectiveAgentIds.length}</dd></div>
    </dl>
  </section>;
}
