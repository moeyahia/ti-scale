import { fetchOverview } from "../../data/api/commandOs";
import { useQuery } from "../../data/cache/QueryProvider";
import { CommandCenterAmbient } from "../../design-system/components/BrandMedia";
import { ButtonLink, Card, EmptyState, ErrorPanel, LoadingPanel, StatusPill } from "../../design-system/components/Primitives";
import type { MissionSummary, OverviewSnapshot, ReadinessCheck } from "../../domain/types/commandOs";
import { operatorText } from "../../lib/operatorLanguage";

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
  const readiness = data ? `${Math.round(data.readiness.score)}/100` : "—";
  return (
    <section className="ti-command-hero" aria-labelledby="ti-command-center-title">
      <div className="ti-command-hero__copy">
        <p className="os-eyebrow">Ti-Scale / live system</p>
        <h1 id="ti-command-center-title">
          <span className="ti-command-hero__title-line"><span>Command</span></span>
          <span className="ti-command-hero__title-line"><span>Center</span></span>
        </h1>
        <p>Operational truth for authorized missions, specialist coordination, evidence, recovery, and the next decision that matters.</p>
        <div className="ti-command-hero__state" role="status">
          <span className={`ti-command-hero__signal${data ? " is-connected" : ""}`} aria-hidden="true" />
          <span>{data ? `Runtime ${data.readiness.status}` : "Connecting to live runtime"}</span>
        </div>
      </div>

      <CommandCenterAmbient />

      <dl className="ti-command-hero__telemetry" aria-label="Live system telemetry">
        <div>
          <dt>Readiness</dt>
          <dd><span key={readiness} className="ti-command-hero__value">{readiness}</span><small>{data ? data.readiness.status : "Live data pending"}</small></dd>
        </div>
        <div>
          <dt>Active missions</dt>
          <dd><span key={data?.summary.activeMissions ?? "pending"} className="ti-command-hero__value">{data?.summary.activeMissions ?? "—"}</span><small>{data ? `${data.summary.activeAgents} agents assigned` : "Live data pending"}</small></dd>
        </div>
        <div>
          <dt>Brain memory</dt>
          <dd><span key={data?.brain.confirmed ?? "pending"} className="ti-command-hero__value">{data?.brain.confirmed ?? "—"}</span><small>{data ? `${data.brain.candidates} candidates to review` : "Live data pending"}</small></dd>
        </div>
        <div>
          <dt>Last event</dt>
          <dd><span key={data?.summary.lastEventAt ?? "pending"} className="ti-command-hero__value ti-command-hero__event-time">{data ? formatDate(data.summary.lastEventAt) : "—"}</span><small>{data ? "Canonical event stream" : "Live data pending"}</small></dd>
        </div>
      </dl>
    </section>
  );
}

function JourneyActions({ data }: { data?: OverviewSnapshot }) {
  const autonomousChecks = data?.readiness.checks.filter((check) => check.journeys.includes("autonomous")) ?? [];
  const guidedChecks = data?.readiness.checks.filter((check) => check.journeys.includes("guided")) ?? [];
  const journeyStatus = (checks: ReadinessCheck[]) => !data ? "unavailable" : checks.some((check) => check.status === "fail") ? "blocked" : checks.some((check) => check.status === "warn") ? "degraded" : "ready";
  return (
    <section className="os-journey-grid" aria-label="Start a mission">
      <article className="os-journey-card os-journey-card--autonomous">
        <div className="os-journey-index" aria-hidden="true">01</div>
        <div className="os-journey-content">
          <p className="os-eyebrow">End-to-end execution</p>
          <h2>Go Autonomous</h2>
          <p>Define the authorized outcome and operating boundaries once. Ti-Scale plans, delegates, recovers, validates, and reports without routine involvement.</p>
          <div className="os-journey-readiness">
            <StatusPill status={journeyStatus(autonomousChecks)} />
            <span>{data ? `${autonomousChecks.filter((check) => check.status === "fail").length} blockers` : "Readiness unavailable"}</span>
          </div>
          <ButtonLink href="/missions/new/autonomous">Compose mission contract</ButtonLink>
        </div>
      </article>

      <article className="os-journey-card os-journey-card--guided">
        <div className="os-journey-index" aria-hidden="true">02</div>
        <div className="os-journey-content">
          <p className="os-eyebrow">Collaborative mastery</p>
          <h2>Start Guided Mission</h2>
          <p>Work step by step. Ti-Scale explains the path, recommends one bounded action, waits for your decision, interprets results, and preserves the record.</p>
          <div className="os-journey-readiness">
            <StatusPill status={journeyStatus(guidedChecks)} />
            <span>{data ? `${guidedChecks.filter((check) => check.status === "fail").length} blockers` : "Readiness unavailable"}</span>
          </div>
          <ButtonLink href="/missions/new/guided" variant="secondary">Create guided mission</ButtonLink>
        </div>
      </article>
    </section>
  );
}

function Dashboard({ data }: { data: OverviewSnapshot }) {
  return (
    <>
      <section className={`os-readiness-band os-readiness-band--${data.readiness.status}`} aria-labelledby="readiness-title">
        <div className="os-readiness-score" aria-label={`Readiness score ${data.readiness.score} out of 100`}>
          <span>{Math.round(data.readiness.score)}</span><small>/100</small>
        </div>
        <div className="os-readiness-copy">
          <span className="os-eyebrow">System readiness</span>
          <h2 id="readiness-title">{data.readiness.status === "ready" ? "Ready for authorized operations" : data.readiness.status === "blocked" ? "Launch blockers require attention" : "Operational with degraded capabilities"}</h2>
          <p>{data.readiness.checks.length} readiness {data.readiness.checks.length === 1 ? "check" : "checks"} evaluated · Last event {formatDate(data.summary.lastEventAt)}</p>
        </div>
        <StatusPill status={data.readiness.status} />
      </section>

      <JourneyActions data={data} />

      <section className="os-metric-row" aria-label="Current operations summary">
        <div><span>Active missions</span><strong key={data.summary.activeMissions}>{data.summary.activeMissions}</strong></div>
        <div><span>Active agents</span><strong key={data.summary.activeAgents}>{data.summary.activeAgents}</strong></div>
        <div><span>Pending decisions</span><strong key={data.summary.pendingDecisions}>{data.summary.pendingDecisions}</strong></div>
        <div><span>Recovering runs</span><strong key={data.summary.recoveringRuns}>{data.summary.recoveringRuns}</strong></div>
      </section>

      <div className="os-dashboard-grid">
        <Card className="os-dashboard-main">
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
                    <span><i style={{ width: `${mission.progress ?? 0}%` }} /></span>
                    <small>{mission.progress === null ? "Progress unavailable" : `${Math.round(mission.progress)}%`}</small>
                  </span>
                  <span className="os-operation-next" title={mission.nextAction ?? undefined}>{operatorText(mission.nextAction, { kind: "next_action", agent: mission.currentOwner?.id }, mission.status)}</span>
                </ButtonLink>
              ))}
            </div>
          )}
        </Card>

        <Card className="os-attention-card">
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
        <Card>
          <div className="os-section-heading"><div><p className="os-eyebrow">Team</p><h2>Agent fleet</h2></div><ButtonLink href="/agents" variant="quiet">Inspect fleet</ButtonLink></div>
          {data.agents.length === 0 ? <p className="os-muted">No agents reported by the runtime.</p> : (
            <ul className="os-compact-list">{data.agents.slice(0, 6).map((agent) => <li key={agent.id}><span><strong>{agent.name}</strong><small>{agent.assignment ?? "Unassigned"}</small></span><StatusPill status={agent.status} /></li>)}</ul>
          )}
        </Card>
        <Card>
          <div className="os-section-heading"><div><p className="os-eyebrow">Knowledge</p><h2>Second Brain pulse</h2></div><ButtonLink href="/brain" variant="quiet">Open Brain</ButtonLink></div>
          <dl className="os-definition-grid">
            <div><dt>Confirmed</dt><dd>{data.brain.confirmed}</dd></div>
            <div><dt>Candidates</dt><dd>{data.brain.candidates}</dd></div>
            <div><dt>Stale</dt><dd>{data.brain.stale}</dd></div>
            <div><dt>Conflicts</dt><dd>{data.brain.conflicts}</dd></div>
          </dl>
          <p className="os-system-line"><span>Vault</span><StatusPill status={data.brain.vaultStatus} /></p>
        </Card>
        <Card>
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
        <Card className="os-readiness-details">
          <div className="os-section-heading"><div><p className="os-eyebrow">Remediation</p><h2>Readiness checks</h2></div></div>
          <ul>{data.readiness.checks.map((check) => <ReadinessCheckRow key={check.id} check={check} />)}</ul>
        </Card>
      )}
    </>
  );
}

export default function OverviewPage() {
  const overview = useQuery("ti-scale-overview", fetchOverview, { staleTime: 10_000 });
  return (
    <div className="os-page os-overview-page">
      <CommandCenterHero data={overview.data} />
      {overview.isLoading && <LoadingPanel />}
      {overview.error && !overview.data && <ErrorPanel error={overview.error} onRetry={overview.refresh} />}
      {!overview.data && <JourneyActions />}
      {overview.data && <Dashboard data={overview.data} />}
      {overview.isRefreshing && <p className="os-refresh-note" role="status">Refreshing operational state…</p>}
    </div>
  );
}
