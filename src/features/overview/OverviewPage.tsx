import { fetchOverview } from "../../data/api/commandOs";
import { useQuery } from "../../data/cache/QueryProvider";
import { ButtonLink, Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import { useMechanicalAssembly } from "../../design-system/hooks/useMechanicalAssembly";
import type { MissionSummary, OverviewSnapshot, ReadinessCheck } from "../../domain/types/commandOs";
import { operatorText } from "../../lib/operatorLanguage";
import { CommandCenterParticleCore } from "./CommandCenterParticleCore";
import {
  journeyModeLabel,
  journeyModePill,
  projectJourneyReadiness,
} from "./journeyReadiness";

function formatDate(value: string | null): string {
  if (!value) return "No events recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Timestamp unavailable" : new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function missionHref(mission: MissionSummary): string {
  return mission.journey === "guided" ? `/guided/${encodeURIComponent(mission.id)}` : `/missions/${encodeURIComponent(mission.id)}`;
}

function ReadinessCheckRow({ check }: { check: ReadinessCheck }) {
  return (
    <li className="os-check-row">
      <StatusPill status={check.status}>{check.status}</StatusPill>
      <div>
        <strong>{check.label}</strong>
        <p>{check.impact}</p>
        {check.remediation && check.status !== "pass" && <small>{check.remediation}</small>}
      </div>
      <span className="os-check-journeys">{check.journeys.map((item) => item === "autonomous" ? "Autonomous" : "Guided").join(" · ")}</span>
    </li>
  );
}

function CommandCenterHero({ data }: { data?: OverviewSnapshot }) {
  const journeys = data ? projectJourneyReadiness(data.readiness.checks) : undefined;
  const runtimeState = journeys
    ? `Guided ${journeyModeLabel(journeys.guided.mode).toLocaleLowerCase("en-US")}; Autonomous ${journeyModeLabel(journeys.autonomous.mode).toLocaleLowerCase("en-US")}`
    : "Connecting to live runtime";
  return (
    <section
      className="ti-command-hero"
      aria-labelledby="ti-command-center-title"
      data-ti-module="hero"
      data-ti-origin="core"
      data-ti-phase="disassembled"
    >
      <div className="ti-command-hero__copy">
        <p className="os-eyebrow">Ti-Scale / live system</p>
        <h1 id="ti-command-center-title">
          <span className="ti-command-hero__title-line"><span>Command</span></span>
          <span className="ti-command-hero__title-line"><span>Center</span></span>
        </h1>
        <p>Operational truth for authorized missions, specialist coordination, evidence, recovery, and the next decision that matters.</p>
        <div className="ti-command-hero__state" role="status">
          <span className={`ti-command-hero__signal${data ? " is-connected" : ""}`} aria-hidden="true" />
          <span>{runtimeState}</span>
        </div>
      </div>

      <CommandCenterParticleCore />

      <dl className="ti-command-hero__telemetry" aria-label="Live system telemetry">
        <div>
          <dt>Autonomous</dt>
          <dd><span className="ti-command-hero__value">{journeys ? journeyModeLabel(journeys.autonomous.mode) : "—"}</span><small>{journeys ? `${journeys.autonomous.blockers} launch blockers` : "Live data pending"}</small></dd>
        </div>
        <div>
          <dt>Guided</dt>
          <dd><span className="ti-command-hero__value">{journeys ? journeyModeLabel(journeys.guided.mode) : "—"}</span><small>{journeys ? `${journeys.guided.blockers} launch blockers` : "Live data pending"}</small></dd>
        </div>
        <div>
          <dt>Brain memory</dt>
          <dd><span key={data?.brain.confirmed ?? "pending"} className="ti-command-hero__value">{data?.brain.confirmed ?? "—"}</span><small>{data ? `${data.brain.pendingReviews} Inbox reviews · ${data.brain.candidateNodes} candidate nodes` : "Live data pending"}</small></dd>
        </div>
        <div>
          <dt>Last event</dt>
          <dd><span key={data?.summary.lastEventAt ?? "pending"} className="ti-command-hero__value ti-command-hero__event-time">{data ? formatDate(data.summary.lastEventAt) : "—"}</span><small>{data ? "Canonical event stream" : "Live data pending"}</small></dd>
        </div>
      </dl>
    </section>
  );
}

function MechanicalConduit() {
  return (
    <div
      className="ti-mechanical-conduit"
      data-ti-module="conduit"
      data-ti-origin="core"
      data-ti-phase="disassembled"
      aria-hidden="true"
    >
      <svg viewBox="0 0 1200 112" preserveAspectRatio="none" focusable="false">
        <path className="ti-mechanical-conduit__spine" pathLength="1" d="M600 0v34M600 34H154v48M600 34h446v48M600 34v65" />
        <path className="ti-mechanical-conduit__signal" pathLength="1" d="M600 0v34M600 34H154v48M600 34h446v48" />
      </svg>
      <span className="ti-mechanical-conduit__lock ti-mechanical-conduit__lock--left" />
      <span className="ti-mechanical-conduit__lock ti-mechanical-conduit__lock--center" />
      <span className="ti-mechanical-conduit__lock ti-mechanical-conduit__lock--right" />
    </div>
  );
}

function JourneyActions({ data }: { data?: OverviewSnapshot }) {
  const journeys = data ? projectJourneyReadiness(data.readiness.checks) : undefined;
  return (
    <section className="os-journey-grid" aria-label="Start a mission">
      <article className="os-journey-card os-journey-card--autonomous" data-ti-plate="keel" data-ti-module="journey" data-ti-origin="left" data-ti-phase="disassembled">
        <div className="os-journey-index" aria-hidden="true">01</div>
        <div className="os-journey-content">
          <p className="os-eyebrow">Contract-bounded execution</p>
          <h2>Go Autonomous</h2>
          <p>Define the authorized outcome and boundaries once. Ti-Scale runs end to end only for the exact capabilities that pass mission preflight; broader templates stay blocked until every required executor is ready.</p>
          <div className="os-journey-readiness">
            <StatusPill status={journeys ? journeyModePill(journeys.autonomous.mode) : "unavailable"}>
              {journeys?.autonomous.mode === "ready" ? "Supported contracts ready" : journeys ? journeyModeLabel(journeys.autonomous.mode) : "Unavailable"}
            </StatusPill>
            <span>{journeys ? `${journeys.autonomous.blockers} launch blockers` : "Readiness unavailable"}</span>
          </div>
          <ButtonLink href="/missions/new/autonomous">Compose mission contract</ButtonLink>
        </div>
      </article>

      <article className="os-journey-card os-journey-card--guided" data-ti-plate="aero" data-ti-module="journey" data-ti-origin="right" data-ti-phase="disassembled">
        <div className="os-journey-index" aria-hidden="true">02</div>
        <div className="os-journey-content">
          <p className="os-eyebrow">Collaborative mastery</p>
          <h2>Start Guided Mission</h2>
          <p>Work step by step. Ti-Scale explains the path, recommends one bounded action, waits for your decision, interprets results, and preserves the record.</p>
          <div className="os-journey-readiness">
            <StatusPill status={journeys ? journeyModePill(journeys.guided.mode) : "unavailable"}>
              {journeys ? journeyModeLabel(journeys.guided.mode) : "Unavailable"}
            </StatusPill>
            <span>{journeys ? `${journeys.guided.blockers} launch blockers` : "Readiness unavailable"}</span>
          </div>
          <ButtonLink href="/missions/new/guided" variant="secondary">Create guided mission</ButtonLink>
        </div>
      </article>
    </section>
  );
}

function Dashboard({ data }: { data: OverviewSnapshot }) {
  const journeys = projectJourneyReadiness(data.readiness.checks);
  const anyJourneyAvailable = journeys.autonomous.mode === "ready"
    || journeys.guided.mode !== "unavailable";
  return (
    <>
      <section className={`os-readiness-band os-readiness-band--${anyJourneyAvailable ? "degraded" : "blocked"}`} aria-labelledby="readiness-title" data-ti-plate="prism" data-ti-module="readiness" data-ti-origin="core" data-ti-phase="disassembled">
        <div className="os-readiness-score" aria-label="Readiness is reported separately for Autonomous and Guided journeys">
          <span>2</span><small>journeys</small>
        </div>
        <div className="os-readiness-copy">
          <span className="os-eyebrow">Journey readiness</span>
          <h2 id="readiness-title">{journeys.guided.mode !== "unavailable" ? "Guided missions are available" : journeys.autonomous.mode === "ready" ? "Supported Autonomous contracts are available" : "Mission journeys need configuration"}</h2>
          <p>Autonomous: {journeyModeLabel(journeys.autonomous.mode)} · Guided: {journeyModeLabel(journeys.guided.mode)} · Last event {formatDate(data.summary.lastEventAt)}</p>
        </div>
        <div className="os-journey-readiness" aria-label="Journey readiness summary">
          <StatusPill status={journeyModePill(journeys.autonomous.mode)}>Autonomous {journeys.autonomous.mode === "ready" ? "supported contracts ready" : journeyModeLabel(journeys.autonomous.mode)}</StatusPill>
          <StatusPill status={journeyModePill(journeys.guided.mode)}>Guided {journeyModeLabel(journeys.guided.mode)}</StatusPill>
        </div>
      </section>

      <MechanicalConduit />
      <JourneyActions data={data} />

      <section className="os-metric-row" aria-label="Current operations summary" data-ti-module="metrics" data-ti-origin="core" data-ti-phase="disassembled">
        <div><span>Active missions</span><strong key={data.summary.activeMissions}>{data.summary.activeMissions}</strong></div>
        <div><span>Active agents</span><strong key={data.summary.activeAgents}>{data.summary.activeAgents}</strong></div>
        <div><span>Pending decisions</span><strong key={data.summary.pendingDecisions}>{data.summary.pendingDecisions}</strong></div>
        <div><span>Recovering runs</span><strong key={data.summary.recoveringRuns}>{data.summary.recoveringRuns}</strong></div>
      </section>

      <div className="os-dashboard-grid">
        <Card className="os-dashboard-main" data-ti-plate="truss" data-ti-module="panel" data-ti-origin="left" data-ti-phase="disassembled">
          <div className="os-section-heading"><div><p className="os-eyebrow">Execution</p><h2>Active operations</h2></div><ButtonLink href="/missions" variant="quiet">View portfolio</ButtonLink></div>
          {data.missions.length === 0 ? (
            <EmptyState title="No active missions" description="Create an Autonomous contract or begin a Guided mission when you are ready." />
          ) : (
            <div className="os-operation-list">
              {data.missions.map((mission) => (
                <ButtonLink
                  key={mission.id}
                  href={missionHref(mission)}
                  variant="quiet"
                  className="os-operation-row"
                  aria-label={`Open active mission ${mission.title} (${mission.id})`}
                >
                  <span className="os-operation-title"><strong>{mission.title}</strong><small>{mission.currentPhase ?? "Phase not reported"}</small></span>
                  <StatusPill status={mission.journey}>{mission.journey === "autonomous" ? "Autonomous" : "Guided"}</StatusPill>
                  <span className="os-operation-progress">
                    <progress
                      aria-label={`${mission.title} progress`}
                      max="100"
                      value={Math.max(0, Math.min(100, mission.progress ?? 0))}
                    />
                    <small>{mission.progress === null ? "Progress unavailable" : `${Math.round(mission.progress)}%`}</small>
                  </span>
                  <span className="os-operation-next" title={mission.nextAction ?? undefined}>{operatorText(mission.nextAction, { kind: "next_action", agent: mission.currentOwner?.id }, mission.status)}</span>
                </ButtonLink>
              ))}
            </div>
          )}
        </Card>

        <Card className="os-attention-card" data-ti-plate="prism" data-ti-module="panel" data-ti-origin="right" data-ti-phase="disassembled">
          <div className="os-section-heading"><div><p className="os-eyebrow">Priority</p><h2>Needs attention</h2></div><span className="os-count">{data.attention.length}</span></div>
          {data.attention.length === 0 ? (
            <EmptyState title="No intervention required" description="Safe stops, Guided decisions, and degraded dependencies will appear here." />
          ) : (
            <ul className="os-attention-list">
              {data.attention.map((item) => (
                <li key={item.id}>
                  <StatusPill status={item.severity} />
                  <div><strong>{item.title}</strong><p>{operatorText(item.summary, { kind: "event" })}</p></div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="os-lower-grid">
        <Card data-ti-plate="keel" data-ti-module="panel" data-ti-origin="left" data-ti-phase="disassembled">
          <div className="os-section-heading"><div><p className="os-eyebrow">Team</p><h2>Agent fleet</h2></div><ButtonLink href="/agents" variant="quiet">Inspect fleet</ButtonLink></div>
          {data.agents.length === 0 ? <p className="os-muted">No agents reported by the runtime.</p> : (
            <ul className="os-compact-list">{data.agents.slice(0, 6).map((agent) => <li key={agent.id}><span><strong>{agent.name}</strong><small>{agent.assignment ?? "Unassigned"}</small></span><StatusPill status={agent.status} /></li>)}</ul>
          )}
        </Card>
        <Card data-ti-plate="aero" data-ti-module="panel" data-ti-origin="core" data-ti-phase="disassembled">
          <div className="os-section-heading"><div><p className="os-eyebrow">Knowledge</p><h2>Second Brain pulse</h2></div><ButtonLink href="/brain" variant="quiet">Open Brain</ButtonLink></div>
          <dl className="os-definition-grid">
            <div><dt>Confirmed</dt><dd>{data.brain.confirmed}</dd></div>
            <div><dt>Candidate nodes</dt><dd>{data.brain.candidateNodes}</dd></div>
            <div><dt>Inbox reviews</dt><dd>{data.brain.pendingReviews}</dd></div>
            <div><dt>Stale</dt><dd>{data.brain.stale}</dd></div>
            <div><dt>Conflicts</dt><dd>{data.brain.conflicts}</dd></div>
          </dl>
          <p className="os-system-line"><span>Vault</span><StatusPill status={data.brain.vaultStatus} /></p>
        </Card>
        <Card data-ti-plate="prism" data-ti-module="panel" data-ti-origin="right" data-ti-phase="disassembled">
          <div className="os-section-heading"><div><p className="os-eyebrow">Infrastructure</p><h2>System health</h2></div><ButtonLink href="/system/connections" variant="quiet">Connections</ButtonLink></div>
          <ul className="os-compact-list">
            <li><span>Database</span><StatusPill status={data.system.database} /></li>
            <li><span>Event stream</span><StatusPill status={data.system.eventStream} /></li>
            <li><span>Providers</span><StatusPill status={data.system.providers} /></li>
            <li><span>MCP</span><StatusPill status={data.system.mcp} /></li>
          </ul>
        </Card>
      </div>

      {data.readiness.checks.some((check) => check.status !== "pass") && (
        <Card className="os-readiness-details" data-ti-plate="truss" data-ti-module="panel" data-ti-origin="core" data-ti-phase="disassembled">
          <div className="os-section-heading"><div><p className="os-eyebrow">Remediation</p><h2>Readiness checks</h2></div></div>
          <ul>{data.readiness.checks.map((check) => <ReadinessCheckRow key={check.id} check={check} />)}</ul>
        </Card>
      )}
    </>
  );
}

export default function OverviewPage() {
  const overview = useQuery("ti-scale-overview", fetchOverview, { staleTime: 10_000 });
  const assemblyRef = useMechanicalAssembly();
  return (
    <div
      className="os-page os-overview-page"
      ref={assemblyRef}
      data-ti-assembly-root="command-center"
      data-ti-assembly="booting"
      data-ti-core-flow="primed"
    >
      <CommandCenterHero data={overview.data} />
      {overview.isLoading && <LoadingPanel />}
      {overview.error && !overview.data && <ErrorPanel error={overview.error} onRetry={overview.refresh} />}
      {!overview.data && <><MechanicalConduit /><JourneyActions /></>}
      {overview.data && <Dashboard data={overview.data} />}
      {overview.isRefreshing && <p className="os-refresh-note" role="status">Refreshing operational state…</p>}
    </div>
  );
}
