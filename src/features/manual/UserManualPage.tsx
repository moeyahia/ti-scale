import { useMemo, useState, type ReactNode } from "react";
import { AppLink } from "../../app/router/navigation";
import { ButtonLink, PageHeader } from "../../design-system/components/Primitives";
import "./user-manual.css";

interface ManualSection {
  id: string;
  title: string;
  eyebrow: string;
  summary: string;
  keywords: string;
  content: ReactNode;
}

function ManualTable({ headings, rows }: { headings: string[]; rows: ReactNode[][] }) {
  return (
    <div className="manual-table-wrap">
      <table className="manual-table">
        <thead><tr>{headings.map((heading) => <th key={heading} scope="col">{heading}</th>)}</tr></thead>
        <tbody>{rows.map((row, rowIndex) => <tr key={rowIndex}>{row.map((cell, cellIndex) => cellIndex === 0 ? <th key={cellIndex} scope="row">{cell}</th> : <td key={cellIndex}>{cell}</td>)}</tr>)}</tbody>
      </table>
    </div>
  );
}

function Callout({ tone = "info", title, children }: { tone?: "info" | "warning" | "success"; title: string; children: ReactNode }) {
  return <aside className={`manual-callout manual-callout--${tone}`}><strong>{title}</strong><div>{children}</div></aside>;
}

function RouteLink({ href, children }: { href: string; children: ReactNode }) {
  return <AppLink href={href} className="manual-route-link">{children}<span className="os-mono">{href}</span></AppLink>;
}

const sections: ManualSection[] = [
  {
    id: "mental-model",
    eyebrow: "Read this first",
    title: "How Ti-Scale organizes work",
    summary: "A Mission is the durable unit of work. An Engagement ID groups related missions; a Run is one execution attempt.",
    keywords: "engagement mission run plan step action evidence finding artifact checkpoint conversation terminology hierarchy",
    content: <>
      <p>Ti-Scale is mission-first, not chat-first. A conversation can explain or control part of a mission, but it is not the owner of execution state.</p>
      <ManualTable headings={["Object", "Meaning", "What you do with it"]} rows={[
        ["Engagement ID", "A stable label that groups related authorized missions and isolates engagement-scoped memory.", "Reuse the same ID for every mission belonging to the same client, lab, assessment, or authorization boundary."],
        ["Mission", "The durable objective, authorization scope, targets, constraints, success criteria, and history.", "Create one whenever you have a new outcome to achieve."],
        ["Run", "One execution attempt for a mission.", "Inspect its execution, control it when allowed, and retain its history without losing the parent mission."],
        ["Plan / Step", "The versioned strategy and a bounded unit of planned work.", "Follow progress in Live Operations or make one deliberate decision at a time in Guided."],
        ["Action", "A tool call, provider turn, delegated task, or operator decision.", "Inspect its purpose, result, linked evidence, and expandable normalized detail where available."],
        ["Evidence / Finding", "Evidence is immutable support; a finding is an evidence-linked conclusion.", "Review provenance before verifying a finding."],
        ["Context Pack", "The exact confirmed memories and verified lessons retrieved for a response or action.", "Open Context used or Show memory path to audit influence."],
      ]} />
      <Callout title="There is no separate Create Engagement page today">
        <p>Starting a new engagement currently means creating its first Mission and entering a new, stable <strong>Engagement ID</strong>. The ID is optional, but leaving it blank means the mission cannot participate in engagement-level grouping or engagement-scoped memory. Ti-Scale does not currently create a separate filesystem engagement record from this field.</p>
      </Callout>
    </>,
  },
  {
    id: "start-engagement",
    eyebrow: "Quick start",
    title: "Start a new engagement",
    summary: "Verify readiness, choose one of the two journeys, set an Engagement ID and explicit authorization scope, then launch the first mission.",
    keywords: "start create new engagement guided autonomous objective scope target authorization readiness launch first mission id",
    content: <>
      <ol className="manual-steps">
        <li><span>1</span><div><h3>Check readiness</h3><p>Use the readiness checks on <AppLink href="/">Overview</AppLink>, inspect provider and MCP history in <AppLink href="/system/connections">System → Connections</AppLink>, and inspect the specialist fleet in <AppLink href="/agents">Agents</AppLink>. Autonomous launch fails closed when an enforcing execution path is unavailable.</p></div></li>
        <li><span>2</span><div><h3>Choose the journey</h3><p>Use <strong>Autonomous</strong> when you can define the full authority and operating contract up front. Use <strong>Guided</strong> when you want explanation and a deliberate decision before each consequential step.</p></div></li>
        <li><span>3</span><div><h3>Create a stable Engagement ID</h3><p>Use a non-secret identifier such as <code>acme-external-2026-q3</code> or <code>htb-lab-july</code>. Reuse it exactly for related missions. Do not put credentials, tokens, personal data, or confidential payloads in the ID.</p></div></li>
        <li><span>4</span><div><h3>Define authorization precisely</h3><p>Both journeys require an authorized objective and confirmation. Guided provides a target/environment field. Autonomous additionally requires allowed targets and action classes and can record prohibited targets, a time window, budgets, and safe-stop rules. Confirm only when you are permitted to perform the described work.</p></div></li>
        <li><span>5</span><div><h3>Launch and supervise</h3><p>Autonomous runs continue under the signed contract without routine prompts. Guided missions open a durable workspace and wait for your decision on the first represented step.</p></div></li>
      </ol>
      <div className="manual-choice-grid">
        <article><p className="os-eyebrow">End-to-end execution</p><h3>Go Autonomous</h3><p>Best when scope, budgets, permitted actions, evidence requirements, and safe-stop rules are known before launch.</p><ButtonLink href="/missions/new/autonomous">Create Autonomous mission</ButtonLink></article>
        <article><p className="os-eyebrow">Step-by-step collaboration</p><h3>Start Guided Mission</h3><p>Best when you want to learn, inspect results, run commands manually, or authorize one exact agent action at a time.</p><ButtonLink href="/missions/new/guided" variant="secondary">Create Guided mission</ButtonLink></article>
      </div>
      <Callout tone="warning" title="Authorization is a real boundary">
        <p>The Engagement ID is only an organizational label. It does not grant authority. The allowed targets, action classes, policies, and explicit authorization confirmation determine what the runtime may do.</p>
      </Callout>
    </>,
  },
  {
    id: "autonomous",
    eyebrow: "Journey 1",
    title: "Autonomous missions",
    summary: "Define the complete operating contract once; Ti-Scale plans, delegates, executes, recovers, validates, and reports inside it.",
    keywords: "autonomous contract outcome scope action classes destructive policy budget retry replan concurrency evidence storage team specialist readiness memory context launch safe stop branch amendment pause abort",
    content: <>
      <p>Open <AppLink href="/missions/new/autonomous">New Autonomous Mission</AppLink>. The six-step composer prevents a run from starting until the contract is executable.</p>
      <ManualTable headings={["Step", "Fields and functions", "Why it matters"]} rows={[
        ["1 · Outcome", "Mission title, authorized objective, measurable success criteria, final deliverables.", "Defines what completion means. Write criteria that can be proved with evidence."],
        ["2 · Authorization & scope", "Engagement ID, allowed and prohibited targets, optional time window, authorization confirmation.", "Constrains every action at execution time. Put CIDRs, hosts, URLs, accounts, or lab identifiers on separate lines."],
        ["3 · Operating contract", "Allowed/prohibited action classes, destructive-action policy, evidence and safe-stop requirements, time/token/cost/retry/replan/concurrency/storage budgets, data and delivery policy.", "Gives the runtime all routine authority it will have after launch. Anything outside it must use a safe alternative or safe-stop."],
        ["4 · Team & readiness", "Live readiness score, enforcing provider paths, MCP health, compatible specialists, runnable reviewed tools.", "Blocks launch when authentication, capabilities, policy enforcement, or required dependencies are missing."],
        ["5 · Context & memory", "Permitted memory scopes and exact memory-node selection.", "Only confirmed, in-scope memory and verified lessons may influence Autonomous execution."],
        ["6 · Review & launch", "Contract summary, version, SHA-256 digest, readiness, authority, budgets, team, memory, safe-stop behavior, deliberate launch confirmation.", "Creates an auditable contract. Review the digest and launch only when the complete boundary is correct."],
      ]} />
      <h3>After launch</h3>
      <ul>
        <li>Use <AppLink href="/live">Live Operations</AppLink> to observe the plan, assignments, semantic actions, heartbeat, progress, current step, and next action. Recovery exposes retry/replan budget use when relevant.</li>
        <li>You may pause or cancel with an audited reason when the run state permits it. Closing the browser does not intentionally stop durable work.</li>
        <li>Autonomous never waits for a routine step approval. An out-of-contract condition must recover in scope or become <strong>Safe-stopped: outside contract</strong>.</li>
        <li>Objective, scope, tools, budget, team, and memory authority cannot be silently changed after launch. The current deployed workspace does not expose a contract-amendment or existing-mission new-run control; stop safely and create a new Mission when a materially different contract is required.</li>
      </ul>
      <Callout tone="success" title="Use Autonomous when the contract is complete">
        <p>A healthy Autonomous run should say <strong>Executing autonomously</strong> or <strong>Recovering autonomously</strong>, then end as <strong>Completed autonomously</strong>, <strong>Safe-stopped</strong>, or <strong>Failed safely</strong>. It should not repeatedly ask you to continue.</p>
      </Callout>
      <p>Finite token or cost limits require exact provider telemetry. If preflight reports that exact accounting is unavailable, leave that optional limit blank or choose a compatible enforcing path; the runtime does not invent an estimate and call it enforcement.</p>
    </>,
  },
  {
    id: "guided",
    eyebrow: "Journey 2",
    title: "Guided missions",
    summary: "Ti-Scale explains one bounded step, recommends it, waits for your choice, interprets the result, records evidence, and advances.",
    keywords: "guided explain recommend choose observe interpret record advance manual run this step i ran it upload result another approach skip stop exact action decision command output teaching depth",
    content: <>
      <p>Open <AppLink href="/missions/new/guided">New Guided Mission</AppLink>. Enter the mission title, authorized objective, target or environment, Engagement ID, desired explanation depth, execution preference, and evidence expectations.</p>
      <ManualTable headings={["Control", "What it does", "Authorization effect"]} rows={[
        ["Explain more", "Expands the current phase, reasoning, prerequisites, risks, expected evidence, and alternatives.", "No execution authority is granted."],
        ["Run this exact step", "Authorizes the agent to execute the one represented action with the displayed normalized parameters.", "Authority applies only to that fingerprint. A material parameter change requires a new decision."],
        ["Paste or upload result", "Submits bounded text output for interpretation and durable unverified evidence recording.", "Interpret only keeps the step paused; it does not attest success or advance."],
        ["Complete exact step and advance", "After you manually performed and reviewed the exact represented action, records your result summary as verified evidence and advances.", "This is the deliberate completion attestation. It is distinct from interpretation."],
        ["Show next step", "Asks Commander to explain the represented next step.", "Planning-only; it does not execute or advance."],
        ["Use another approach", "Asks Commander to compare another in-scope approach using optional context you provide.", "Planning-only; it explicitly does not reject or change the plan."],
        ["Reject and replan", "Rejects the exact pending decision with a required reason and requests a materially different represented action.", "The rejected action remains unauthorized."],
        ["Context used", "Shows the exact persisted memory context behind a Commander response.", "Inspection only; no authority is granted."],
        ["Remember this / Do not remember this", "Creates a reviewable Memory Inbox candidate, or declines/suppresses retention.", "Nothing becomes reusable memory until its lifecycle and consent rules permit it."],
        ["Skip", "Records an audited reason and marks only the represented step skipped.", "The mission continues when a valid next step exists."],
        ["Stop mission", "Stops the whole mission after an explicit reason and confirmation.", "Cancellation propagates to active child work."],
      ]} />
      <h3>The Guided loop</h3>
      <ol className="manual-inline-steps"><li>Explain</li><li>Recommend</li><li>Choose</li><li>Observe</li><li>Interpret</li><li>Record</li><li>Advance</li></ol>
      <p>The workspace persists the current phase, checkpoint, conversation, decision, evidence, findings, and specialist handoffs independently of the visible chat transcript. Leave and return through <AppLink href="/guided">Guided Workspace</AppLink>.</p>
      <p>Manual result interpretation accepts bounded text or <code>.txt</code>, <code>.log</code>, <code>.json</code>, <code>.csv</code>, and <code>.xml</code> files up to 128 KiB. Binary evidence cannot be submitted through this conversation control, and the current UI has no general binary Evidence Vault uploader. Interpret-only output is hashed, redacted, and retained as unverified evidence while the step remains paused.</p>
      <Callout title="Manual versus single-step agent execution">
        <p>Choose <strong>manual</strong> during mission creation when you normally want to run commands yourself. Choose <strong>single-step agent execution</strong> when you want the Run this exact step option where policy permits. Neither preference creates blanket authority.</p>
      </Callout>
    </>,
  },
  {
    id: "shell-navigation",
    eyebrow: "Global controls",
    title: "Application shell, navigation, and command palette",
    summary: "The stable shell provides primary navigation, live-stream health, keyboard search, and mobile navigation.",
    keywords: "shell sidebar navigation command palette ctrl k live stream connected fallback offline mobile menu skip link keyboard",
    content: <>
      <ManualTable headings={["Function", "How to use it", "What it tells you"]} rows={[
        ["Primary navigation", "Use the left sidebar; on mobile open it with the menu button.", "The highlighted item is the active product area."],
        ["Command palette", "Press Ctrl+K or ⌘K, type a page, mission, run, decision, agent, or memory, then use arrow keys and Enter.", "Provides navigation and exactly two launch commands: Autonomous and Guided."],
        ["Live status", "Read the top-right stream indicator.", "Live means events are connected; reconnecting is temporary; fallback uses periodic authoritative refresh; offline shows last validated state."],
        ["Skip to content", "Press Tab from the top of a page and activate Skip to content.", "Moves keyboard focus past repeated navigation."],
      ]} />
      <p>Inside a mission or run, the command palette can also offer state-valid Pause, Resume, or Cancel controls with an audited reason; cancellation requires explicit confirmation. In a current Guided step it may create a reviewable Memory Inbox candidate from the latest Commander insight. Escape closes an editor or the palette and restores focus. Most operational filters are stored in the URL so a view can be bookmarked.</p>
    </>,
  },
  {
    id: "overview-missions",
    eyebrow: "Portfolio control",
    title: "Overview and Missions",
    summary: "Overview answers what needs attention now; Missions is the durable portfolio and entry point for new work.",
    keywords: "overview command center readiness active operations needs attention agent fleet brain pulse health missions portfolio filters search saved views export board table new mission",
    content: <>
      <h3>Overview</h3>
      <ul>
        <li><strong>Go Autonomous / Start Guided Mission:</strong> the only two top-level journey choices.</li>
        <li><strong>Readiness:</strong> combined provider, MCP, policy, database, event-stream, and worker readiness. Failed checks include impact and remediation.</li>
        <li><strong>Active operations:</strong> current mission, journey, phase, owner, progress, and next action.</li>
        <li><strong>Needs attention:</strong> Guided decisions, Autonomous safe stops, degraded dependencies, recovery, policy events, and budget problems.</li>
        <li><strong>Agent fleet / Second Brain pulse / System health:</strong> concise live summaries with links to the full surfaces.</li>
      </ul>
      <h3>Missions portfolio</h3>
      <p>Open <AppLink href="/missions">Missions</AppLink> to inspect the durable mission table and each mission’s journey, state, phase, progress, next action, and last update. Select a mission to open its workspace. <strong>New mission</strong> returns to the two-journey selector.</p>
      <p>A mission can have multiple runs. A failed or cancelled run does not delete the mission, its evidence, or its history.</p>
      <p>The current deployed portfolio does not expose boards, saved views, archive/delete, bulk export, or a control to add another run to an existing mission.</p>
    </>,
  },
  {
    id: "workspaces-recovery",
    eyebrow: "Execution control",
    title: "Mission workspace, Live Operations, and recovery",
    summary: "Every active run exposes journey, owner, heartbeat, progress, next action, plan, evidence, and recovery state.",
    keywords: "mission workspace live operations run status heartbeat owner progress plan event pause resume cancel recovery checkpoint loop stalled retry replan branch terminal console",
    content: <>
      <ManualTable headings={["Surface", "Use it for", "Primary controls"]} rows={[
        ["Mission / Run workspace", "The durable mission header, authorization, journey, plan versions, steps, assignments, semantic events, evidence and history.", "Open run, inspect detail, and use pause, resume, or cancel when the backend says the transition is valid."],
        ["Live Operations", "Observe all active Autonomous work or focus one run.", "Select a run; inspect phase/step ownership, intent, rationale, heartbeat, progress, recovery, Context used where linked, and expandable normalized details."],
        ["Guided Workspace", "Continue one collaborative mission from its exact checkpoint.", "Make the pending exact-step decision, submit manual output, inspect interpretation, or stop."],
        ["Expandable details", "Normalized action and event JSON exposed inline where the deployed view provides it.", "Expand only when needed; semantic events remain the primary operator feed. There is no general raw-terminal drawer in this deployment."],
      ]} />
      <h3>Mission workspace tabs</h3>
      <ManualTable headings={["Tab", "What it contains"]} rows={[
        ["Summary", "Objective, authorization and engagement scope, phase, blocker, progress, current owner, next action, recent semantic events, and Completion Review for terminal runs."],
        ["Plan", "Plan version, strategy, rationale, ordered phases and steps, owner, risk, target, reversibility, intent, and expandable normalized action detail."],
        ["Live / Guide", "Autonomous cockpit for Autonomous runs; represented step and exact decision link for Guided runs."],
        ["Evidence", "Mission-scoped immutable evidence and links into Intelligence."],
        ["Findings", "Mission-scoped evidence-linked conclusions and review state."],
        ["Conversation", "Collaborative Commander in Guided; read-only semantic observer history in Autonomous."],
        ["Brain", "Mission-isolated memory nodes, Context Packs, memory influence, and graph link."],
        ["Learning", "Run evaluations, candidate lessons, verified lessons, and measured reuse."],
        ["History", "Append-only semantic events, correlation, Context used, and expandable technical details."],
        ["Settings", "Read-only journey, authorization, Engagement ID, memory policy, scope, criteria, stable IDs, and attached run attempts."],
      ]} />
      <h3>When work stalls</h3>
      <ol>
        <li>Check the status, heartbeat, last meaningful event, retry/replan counters, and next expected transition.</li>
        <li>Open the Recovery panel to see the diagnosis, last durable checkpoint, attempts already made, and related failed-attempt memory.</li>
        <li>For Autonomous, allow bounded in-contract recovery or inspect the safe-stop report. It must not wait indefinitely for approval.</li>
        <li>For Guided, choose the recommended recovery step, an alternative, or stop. The system waits for that explicit choice.</li>
        <li>Use Pause, Resume, or Cancel only with a clear audited reason. Resume is currently offered from a valid blocked checkpoint; cancellation should end child work and release leases.</li>
      </ol>
      <p>Recovery may explain replan, reassign, or provider-change alternatives, but those controls are currently disabled when no safe operator endpoint exists. The functional recovery controls are resume from a valid checkpoint and terminate gracefully.</p>
      <Callout tone="warning" title="Do not treat terminal output as progress">
        <p>Meaningful progress is a state advance, unique evidence, a strengthened finding, resolved dependency, valid plan change, produced artifact, or measurable reduction in uncertainty. Repeated command output with no evidence delta should transition to recovery.</p>
      </Callout>
      <h3>Completion Review</h3>
      <p>For completed, failed, or cancelled runs, review the terminal reason, success criteria, any persisted evaluation, evidence/findings coverage, elapsed time, retries, recoveries, policy events, safe stops, comparable prior work when available, artifacts, reports, memory and lessons used, unresolved steps, and unreviewed findings. The authorized completion export is a bounded metadata bundle; it excludes raw evidence, credentials, provider/tool payloads, artifact paths, and memory bodies.</p>
    </>,
  },
  {
    id: "decisions",
    eyebrow: "Human authority",
    title: "Decisions",
    summary: "The deployed inbox separates exact Guided-step decisions from Autonomous safe-stop and runtime attention records.",
    keywords: "decisions guided exact step authorize run manually reject replan skip stop autonomous safe stop exception attention reason expiry parameters",
    content: <>
      <p>Open <AppLink href="/decisions">Decisions</AppLink>. The deployed filters narrow by Run ID and decision state.</p>
      <ManualTable headings={["Decision type", "Available action", "Important boundary"]} rows={[
        ["Guided exact step", "Run the exact step, open result review for manual output, reject and replan, skip with reason, or stop the mission.", "Inspect target, normalized parameters, risk, reversibility, evidence expectation, and expiry before acting."],
        ["Autonomous safe stop / runtime attention", "Open the related run context when a link is available and review what was outside contract or failed safely.", "This is exception visibility, not a routine mid-run approval. Resume only through a valid in-scope recovery path."],
      ]} />
      <p>The deployed page has no Autonomous contract queue or administrative approve/reject form. The <code>/approvals</code> compatibility address redirects here. Autonomous work must not wait here for routine approval.</p>
    </>,
  },
  {
    id: "intelligence",
    eyebrow: "Evidence integrity",
    title: "Intelligence: evidence, findings, and artifacts",
    summary: "Review immutable evidence provenance, evidence-gated findings, and artifact metadata without mixing them together.",
    keywords: "intelligence evidence vault finding artifact hash provenance chain custody confidence sensitivity verification review accepted risk override remediation download export",
    content: <>
      <p>Open <AppLink href="/intelligence/evidence">Intelligence</AppLink> and switch among Evidence, Findings, and Artifacts.</p>
      <ManualTable headings={["View", "What is shown", "What you can do"]} rows={[
        ["Evidence", "Source, acquisition time, target, type, content hash, confidence, sensitivity, verification state, provenance, and chain-of-custody events.", "Search/filter, select a record, and inspect immutable support. This screen currently has no general evidence upload or evidence-review mutation."],
        ["Findings", "Title, severity, affected scope, description, impact, remediation, confidence, linked evidence counts, and review state.", "Record under-review, verified, rejected, or accepted-risk decisions with a reason. Verification is blocked without evidence unless you explicitly use the separately audited override."],
        ["Artifacts", "Artifact type, mission, media type, byte size, content hash, storage scheme/availability, and returned metadata.", "Inspect metadata. Sensitivity and Context used appear on Reports where returned, not on generic Artifact detail. This surface does not expose raw artifact download."],
      ]} />
      <Callout title="Evidence and findings are deliberately different">
        <p>Evidence says what was observed. A finding says what the evidence supports. Correcting or rejecting a finding never mutates its underlying evidence record.</p>
      </Callout>
    </>,
  },
  {
    id: "agents",
    eyebrow: "Specialist fleet",
    title: "Agents and delegation",
    summary: "Inspect real specialist capability, provider/tool policy, assignments, queue depth, heartbeat, and recorded outcomes.",
    keywords: "agents commander specialist delegation capability mcp provider health heartbeat queue assignment success retry recovery policy tool no hands",
    content: <>
      <p>Open <AppLink href="/agents">Agents</AppLink>. Select an agent to see its role, status, declared capabilities, provider/tool policy, version, assignment health, and recent assignments. This surface is currently read-only; assignment and reassignment remain automatic.</p>
      <ul>
        <li><strong>Commander:</strong> plans, routes, supervises, evaluates, and synthesizes. It should not silently absorb specialist execution.</li>
        <li><strong>Specialists:</strong> perform bounded domain work using their declared tools and capabilities.</li>
        <li><strong>Status and heartbeat:</strong> distinguish available, busy, degraded, offline, and quarantined workers.</li>
        <li><strong>Queue and outcomes:</strong> show queue depth, active/completed/failed counts, success rate, mean completion time, recent assignments, and lease expiry where returned.</li>
      </ul>
      <p>Provider selection is normally policy-driven. It is not a third journey. A provider that cannot enforce the Autonomous boundary may advise or analyze, but must not be represented as the enforcing executor.</p>
    </>,
  },
  {
    id: "second-brain",
    eyebrow: "User-owned memory",
    title: "Second Brain and Obsidian",
    summary: "Search and graph memory, review candidates, correct or retire confirmed nodes, control retrieval, and synchronize a server-local Obsidian vault.",
    keywords: "second brain memory graph inbox node context pack preferences provenance lifecycle candidate confirmed verified disputed stale superseded forgotten scope sensitivity confidence obsidian vault export import sync conflict pin shortest path privacy",
    content: <>
      <ManualTable headings={["Surface", "Functions"]} rows={[
        ["Brain Home", "Memory health, graph growth, search across title/summary/note text, type/lifecycle/sensitivity filters, confidence, source count, and vault health."],
        ["Memory Graph", "Global, local, mission, Operator profile, Attack path, and Lessons & failures views; visible-graph search; node/edge/scope/engagement/lifecycle/sensitivity/confidence/date filters; compact or clustered layout; label density; zoom, fit, reset, saved browser-local views, shareable links, shortest paths, bounded expansion, and an accessible table."],
        ["Memory Inbox", "Inspect the source excerpt and proposal reason; edit title, summary, body, sensitivity, and global/engagement/mission scope before confirming; confirm, reject, or reject and suppress relearning."],
        ["Memory Node", "Read the note, provenance, backlinks, outgoing relationships, versions, contradictions, and usage. Correct title/summary/body/sensitivity with a reason, pin/unpin, set expiry, dispute, show in graph, open vault controls, or permanently forget."],
        ["Memory Control Center", "Enable/disable retrieval, choose candidate-only or disabled preference learning, operational-memory retention, expiry, Autonomous/Guided use, and Obsidian sync scope. Engagement isolation and secret exclusion remain enforced."],
        ["Obsidian Vault", "Connect a relative path inside the server-configured allowed root with explicit permission; synchronize, export canonical notes, import operator edits, create a portable ZIP, use offered Obsidian links, inspect note state, and resolve conflicts by deliberately choosing the database or vault version."],
      ]} />
      <Callout title="The vault path is on the Ti-Scale server">
        <p>It is not a path on the Mac running your browser. The server accepts only a relative path inside its configured vault root. Use portable ZIP export or an administrator-approved filesystem synchronization method to move a vault to another computer.</p>
      </Callout>
      <h3>Lifecycle</h3>
      <ol className="manual-inline-steps"><li>Candidate</li><li>Confirmed</li><li>Verified</li><li>Disputed</li><li>Stale</li><li>Superseded</li><li>Forgotten</li></ol>
      <p><strong>Context used</strong> shows which memories were retrieved, which were actually used, why each was relevant, what influence it had, and why another was ignored. <strong>Show memory path</strong> opens those nodes and relationships in the graph. This is an evidence-based influence explanation, not hidden chain-of-thought.</p>
      <Callout tone="warning" title="Forgetting is different from rejecting">
        <p>Rejecting a candidate prevents promotion. Reject and do not relearn adds a privacy-safe suppression. Forgetting removes content, embeddings, derived links, synchronized projections, and cached retrieval context, leaving only a content-free audit event.</p>
      </Callout>
    </>,
  },
  {
    id: "learning",
    eyebrow: "Measured improvement",
    title: "Learning Lab",
    summary: "Review evidence-linked candidate lessons, terminal-run evaluations, and measured reuse without allowing agents to approve their own changes.",
    keywords: "learning lesson candidate proposed under review verified rejected stale superseded evaluation usage impact evidence review benchmark self improvement failed attempt",
    content: <>
      <p>Open <AppLink href="/learning">Learning</AppLink> and use its views:</p>
      <ul>
        <li><strong>Lessons:</strong> filter by lifecycle, inspect statement, type, scope, confidence, expected benefit, author, supporting/counter evidence, failed-attempt category, retry conditions, usage, and related mission context.</li>
        <li><strong>Independent review:</strong> move a lesson to under review, verified, rejected, stale, or superseded with a reason. An agent cannot verify its own proposal.</li>
        <li><strong>Evaluations:</strong> compare journey adherence, objective completion, evidence quality, policy compliance, efficiency, retries, recovery, delegation, memory usefulness, and retrospective.</li>
        <li><strong>Usage & impact:</strong> see where verified lessons were selected, what they influenced, and whether measurable performance changed.</li>
      </ul>
      <p>A candidate lesson is not active policy. Verification does not grant authority to edit production code, change scope, weaken safety rules, add tools, or modify credentials.</p>
    </>,
  },
  {
    id: "observability",
    eyebrow: "Operational truth",
    title: "Observability",
    summary: "Inspect semantic Events, redacted structured Logs, and generic component Health snapshots from canonical state.",
    keywords: "observability events logs health severity correlation filter search cursor raw json event stream component",
    content: <>
      <p>Open <AppLink href="/observability">Observability</AppLink>. Use URL-backed filters and cursor pagination instead of loading the entire history.</p>
      <ManualTable headings={["View", "Use it for"]} rows={[
        ["Events", "Filter semantic state changes by the controls shown, inspect journey and correlation identifiers, and expand the redacted structured payload."],
        ["Logs", "Full-text search redacted structured log messages, filter by severity, and inspect domain, correlation, timestamp, and expandable attributes."],
        ["Health", "Filter returned component snapshots by component/state and inspect their status, message, timestamp, and generic metrics. Only metrics actually returned by the backend are shown."],
      ]} />
      <p>The deployed page has no separate Traces tab or waterfall. Trace IDs shown on records are correlation data, not a promise of a dedicated trace viewer.</p>
      <p>Expand raw payloads only when diagnosis requires them. Secrets and unredacted authentication material should never appear in logs.</p>
    </>,
  },
  {
    id: "reports-system",
    eyebrow: "Outputs and configuration",
    title: "Reports and System",
    summary: "Reports exposes durable mission deliverable metadata; System exposes redacted provider history, MCP registry, policy, and health state.",
    keywords: "reports output artifact hash coverage download system connections providers mcp policies settings read only health configuration",
    content: <>
      <h3>Reports</h3>
      <p>Open <AppLink href="/reports">Reports</AppLink>. Select a report to inspect its mission, journey, media type, byte size, content hash, sensitivity, evidence coverage, storage availability, metadata, and memory Context used. The current report page is metadata-only; terminal Completion Review can export a scope-checked metadata bundle, not raw evidence or artifacts.</p>
      <h3>System</h3>
      <ul>
        <li><AppLink href="/system/connections">Connections</AppLink>: provider status inferred from durable provider-turn history, turn/failure/latency metrics, and MCP registry status, transport, redacted endpoint, capabilities, policy, and last check.</li>
        <li><AppLink href="/system/policies">Policies</AppLink>: redacted authorization, runtime, agent, and MCP policy projections. Inspect source, sensitivity, update time, and document.</li>
        <li><AppLink href="/system/settings">Settings</AppLink>: canonical component-health and policy-count status. It is intentionally read-only and does not expose OpenAPI/event-contract links in this deployment.</li>
      </ul>
      <Callout title="A healthy connection is not authority">
        <p>A healthy MCP check or successful provider-turn history is operational evidence, not execution authority. The mission contract, exact Guided decision, tool policy, scope validation, and specialist capability still determine whether anything may act.</p>
      </Callout>
    </>,
  },
  {
    id: "statuses",
    eyebrow: "State language",
    title: "Status and lifecycle reference",
    summary: "Run states are deterministic; journey-specific language tells you whether the system should continue, wait, recover, or stop.",
    keywords: "status queued planning awaiting contract confirmation running waiting guided decision blocked recovering completed failed cancelled executing autonomously safe stopped heartbeat",
    content: <>
      <ManualTable headings={["State", "Meaning", "Operator expectation"]} rows={[
        ["queued", "Durable work exists but has not acquired execution ownership.", "Wait briefly; investigate queue/worker health if no owner appears."],
        ["planning", "The plan is being created or materially revised.", "Expect phase, owner, heartbeat, elapsed time, and next transition."],
        ["awaiting_contract_confirmation", "An Autonomous contract draft is ready before launch.", "Review scope, budgets, enforcement, team, memory, digest, and deliberately launch or edit."],
        ["running", "Authorized execution is active.", "Watch meaningful progress, heartbeat, current step, and next action."],
        ["waiting_guided_decision", "A Guided run is waiting for one identified exact decision.", "Open Guided Workspace or Decisions and act on that card."],
        ["recovering", "The supervisor detected failure, stagnation, a lost lease, or an unhealthy dependency and is using a bounded recovery policy.", "Inspect diagnosis, checkpoint, attempts, budget, and proposed recovery."],
        ["blocked", "No valid next transition is currently available.", "Read the human reason and remediation; do not keep clicking Continue without new information."],
        ["completed", "The run reached its terminal success state.", "Review completion, evidence, findings, reports, memory candidates, and lessons. A persisted evaluation may still be absent or pending."],
        ["failed", "The run ended safely without completing its objective.", "Review end reason, evidence retained, exception report, and whether a separate run is justified."],
        ["cancelled", "An audited cancellation became terminal and child work should be stopped.", "Confirm no assignment remains ghost-active; use Observability if one does."],
      ]} />
      <p>Imported status names such as <code>waiting_input</code> or <code>awaiting_action_approval</code> are compatibility values and should not appear as new journey choices.</p>
    </>,
  },
  {
    id: "safety-privacy",
    eyebrow: "Non-negotiable controls",
    title: "Authorization, safety, privacy, and audit",
    summary: "Scope and policy are enforced at action time; memory is transparent and isolated; evidence and critical decisions are auditable.",
    keywords: "safety authorization scope target action policy secret redaction privacy audit engagement isolation retention forgetting evidence guided autonomous destructive risk credentials",
    content: <>
      <ul>
        <li>Use Ti-Scale only for work you are authorized to perform. Keep the mission’s allowed and prohibited target boundary precise and current.</li>
        <li>Autonomous authority comes only from the signed, versioned contract. Guided authority comes only from the exact represented step decision.</li>
        <li>Personal preferences may change explanation depth, pace, tool preference, layout, or report style; they may never weaken authorization, evidence, or safety requirements.</li>
        <li>Engagement-scoped memory must not cross into another engagement. Exact scope wins over general preference.</li>
        <li>Credentials, API keys, tokens, private keys, authentication material, and raw confidential payloads do not belong in Engagement IDs, reusable memory, notes, or logs.</li>
        <li>Evidence, finding review, contract confirmation, decisions, policy events, memory use/correction/forgetting, lesson review, and cancellation are recorded for audit.</li>
        <li>Use explicit forget/export/retention controls. Disabling retrieval does not silently delete retained records; forgetting is the deletion workflow.</li>
      </ul>
    </>,
  },
  {
    id: "current-limitations",
    eyebrow: "Current product boundary",
    title: "Functions that are not available in the current UI",
    summary: "This manual distinguishes working controls from planned or backend-only capabilities so you do not search for buttons that do not exist.",
    keywords: "limitations unavailable missing cannot engagement manager new run amendment agent assignment upload download settings authenticate install mcp imported pagination",
    content: <>
      <ManualTable headings={["Not currently exposed", "What to do today"]} rows={[
        ["Separate Engagement manager", "Create the first Mission, enter a stable Engagement ID, and reuse the exact ID. This does not create the old filesystem engagement workspace."],
        ["Add a run to an existing Mission", "The workspace displays multiple runs but has no creation control. Create a new Mission for a new attempt until a versioned run-creation workflow is exposed."],
        ["Amend an active contract or scope", "The mission Settings view is read-only. Stop safely and create a correctly scoped Mission; never treat chat text as a contract amendment."],
        ["Manual agent assignment or reassignment", "Inspect fleet capability and health. Assignment is policy-driven; Recovery can explain reassignment but cannot invoke it without a safe endpoint."],
        ["Install, authenticate, or repair providers/MCP", "System reports redacted health and policy only. Perform administrative connection setup outside this read-only UI, then recheck readiness."],
        ["General evidence upload", "Guided accepts bounded text for interpretation. A generic binary Evidence Vault uploader is not exposed."],
        ["Generic raw artifact/report download", "Use metadata inspection and the terminal scope-checked completion export. Raw delivery requires a separate authorized artifact endpoint."],
        ["Editable System settings", "Inspect canonical health and policy status. Configuration mutations are withheld until a versioned safe endpoint exists; this deployed Settings page does not link API/event contracts."],
        ["Imported application history", "Imported records are read-only compatibility data until explicitly transferred into a Ti-Scale run."],
      ]} />
      <Callout title="Why the manual states limitations">
        <p>Showing an unavailable control as if it worked would be dangerous in an authorized operations product. A missing button is a product gap, not implied permission to bypass the runtime through a shell or hidden route.</p>
      </Callout>
    </>,
  },
  {
    id: "troubleshooting",
    eyebrow: "When something is wrong",
    title: "Troubleshooting guide",
    summary: "Use visible state, last event, heartbeat, remediation, and correlated observability before retrying or restarting anything.",
    keywords: "troubleshooting stuck stale down cannot launch readiness blocked provider mcp offline fallback connection no scroll guided waiting safe stop report evidence memory obsidian conflict refresh cache restart",
    content: <>
      <ManualTable headings={["Symptom", "Check", "Safe response"]} rows={[
        ["Autonomous launch is blocked", "Readiness failures, authorization confirmation, allowed targets/actions, budgets, automatic specialist availability, enforcing provider, and MCP health.", "Fix the named preflight blocker; do not bypass readiness."],
        ["Guided mission is not moving", "Run state and the exact pending decision in Guided Workspace or Decisions.", "Choose, submit output, request another approach, skip with reason, or stop. Guided is designed to wait."],
        ["Autonomous looks stuck", "Heartbeat, last meaningful event, progress signature, retry/replan budget, provider/MCP status, and Recovery panel.", "Let bounded recovery finish, then inspect safe stop or pause/cancel with a reason. Repeated Continue messages are not a fix."],
        ["An agent remains active after completion", "Assignments, leases, terminal run state, child processes, and correlated events in Observability.", "Cancel/terminate through the run control if available; treat ghost-active state as a runtime fault."],
        ["Overview contains many old blocked items", "Check mission timestamps and import provenance.", "Imported nonterminal history may be deliberately blocked for review. Do not resume every historical item blindly."],
        ["Live indicator says fallback/offline", "Network tunnel, server health, event-stream endpoint, last acknowledged sequence.", "Authoritative pages may refresh at low frequency in fallback. Restore connectivity before making time-sensitive decisions."],
        ["Evidence or report cannot download", "Artifact storage availability and whether a verified delivery endpoint is shown.", "Do not infer that a metadata record is downloadable. Use the configured export/delivery path."],
        ["Memory was wrong", "Open Context used, then the node’s provenance, scope, confidence, and versions.", "Correct content/sensitivity, dispute, expire, or forget it. Scope is not editable after confirmation; forget and recreate/reconfirm a candidate with the correct scope when necessary."],
        ["Obsidian changes did not synchronize", "Vault permission, allowed path, connection state, note sync state, quarantine, and conflicts.", "Run sync/import, review malformed notes, and resolve conflicts explicitly; never overwrite blindly."],
        ["A page appears stale after deployment", "Top-right stream state, browser cache, current URL, and server version/health.", "Use a normal reload first, then a hard reload if assets changed. Preserve run state; do not restart execution solely to refresh the UI."],
      ]} />
    </>,
  },
  {
    id: "route-index",
    eyebrow: "Complete function index",
    title: "Routes and direct links",
    summary: "Use this map to open every current Ti-Scale product surface directly.",
    keywords: "routes links all pages complete index overview missions live guided decisions intelligence agents brain learning observability reports system manual",
    content: <>
      <div className="manual-route-grid">
        <RouteLink href="/">Command Center</RouteLink>
        <RouteLink href="/missions">Missions portfolio</RouteLink>
        <RouteLink href="/missions/new">Choose a journey</RouteLink>
        <RouteLink href="/missions/new/autonomous">Autonomous contract</RouteLink>
        <RouteLink href="/missions/new/guided">Guided creation</RouteLink>
        <RouteLink href="/live">Live Operations</RouteLink>
        <RouteLink href="/guided">Guided Workspace</RouteLink>
        <RouteLink href="/decisions">Decisions</RouteLink>
        <RouteLink href="/intelligence/evidence">Evidence</RouteLink>
        <RouteLink href="/intelligence/findings">Findings</RouteLink>
        <RouteLink href="/intelligence/artifacts">Artifacts</RouteLink>
        <RouteLink href="/agents">Agents</RouteLink>
        <RouteLink href="/brain">Second Brain</RouteLink>
        <RouteLink href="/brain/graph">Memory Graph</RouteLink>
        <RouteLink href="/brain/inbox">Memory Inbox</RouteLink>
        <RouteLink href="/brain/control">Memory Control Center</RouteLink>
        <RouteLink href="/brain/vault">Obsidian Vault</RouteLink>
        <RouteLink href="/learning">Learning Lab</RouteLink>
        <RouteLink href="/observability">Observability</RouteLink>
        <RouteLink href="/reports">Reports</RouteLink>
        <RouteLink href="/system/connections">System Connections</RouteLink>
        <RouteLink href="/system/policies">System Policies</RouteLink>
        <RouteLink href="/system/settings">System Settings & contracts</RouteLink>
        <RouteLink href="/manual">User Manual</RouteLink>
      </div>
      <p>Detail routes are created by selecting a mission, run, evidence record, finding, artifact, agent, memory node, lesson, or report. Their stable IDs appear in the URL and can be bookmarked.</p>
    </>,
  },
  {
    id: "keyboard-mobile",
    eyebrow: "Accessible operation",
    title: "Keyboard, mobile, and readable use",
    summary: "The same core mission, decision, recovery, and memory functions remain reachable without a mouse and on smaller screens.",
    keywords: "keyboard mobile accessibility screen reader reduced motion focus zoom touch target command palette escape tab arrow canvas table responsive",
    content: <>
      <ul>
        <li><strong>Ctrl+K / ⌘K:</strong> open the command palette. Type to search; use arrows and Enter to select; Escape closes and restores focus.</li>
        <li><strong>Tab / Shift+Tab:</strong> move through controls. The first Tab exposes Skip to content. A visible outline shows focus.</li>
        <li><strong>Mobile:</strong> use the top-left menu; contextual rails become stacked panels or drawers. Pause, exact Guided decision, Autonomous abort, and recovery controls remain reachable.</li>
        <li><strong>Memory graph:</strong> use arrow keys to select visible nodes and Escape to clear. Use the Accessible table toggle when canvas navigation is unsuitable.</li>
        <li><strong>Reduced motion and zoom:</strong> operating state must remain understandable with reduced motion and at 200% zoom. Color is supplemented with labels and shapes.</li>
        <li><strong>Raw data:</strong> expandable JSON and technical output are secondary; semantic labels and status announcements are the primary accessible representation.</li>
      </ul>
    </>,
  },
];

export default function UserManualPage() {
  const [query, setQuery] = useState("");
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const visibleSections = useMemo(() => {
    if (!normalizedQuery) return sections;
    return sections.filter((section) => `${section.title} ${section.summary} ${section.keywords}`.toLocaleLowerCase().includes(normalizedQuery));
  }, [normalizedQuery]);

  return (
    <div className="os-page manual-page">
      <PageHeader
        eyebrow="Command Intelligence · 2.4 live"
        title="Ti-Scale Operator Manual"
        description="A complete operator guide to starting engagements, running Autonomous and Guided missions, supervising agents, reviewing evidence, recovering stalled work, and controlling the Second Brain."
        actions={<ButtonLink href="/missions/new">Start a mission</ButtonLink>}
      />

      <section className="manual-answer" aria-labelledby="manual-direct-answer">
        <div><p className="os-eyebrow">Direct answer</p><h2 id="manual-direct-answer">To start a new engagement, create its first Mission</h2></div>
        <p>Choose <strong>Go Autonomous</strong> or <strong>Start Guided Mission</strong>, enter a new stable <strong>Engagement ID</strong>, define the authorized objective and target scope, then launch. Reuse that Engagement ID for later missions in the same body of work.</p>
        <div><ButtonLink href="/missions/new/autonomous">Go Autonomous</ButtonLink><ButtonLink href="/missions/new/guided" variant="secondary">Start Guided Mission</ButtonLink><a className="os-button os-button--quiet" href="#start-engagement">Read the walkthrough</a></div>
      </section>

      <div className="manual-layout">
        <aside className="manual-toc" aria-label="User manual contents">
          <label htmlFor="manual-search">Search this manual</label>
          <div className="manual-search"><svg aria-hidden="true" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7" /><path d="m16 16 5 5" /></svg><input id="manual-search" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Try: engagement, recovery…" /></div>
          <p role="status" aria-live="polite">{visibleSections.length} of {sections.length} sections</p>
          <nav aria-label="Manual sections">
            {visibleSections.map((section) => <a key={section.id} href={`#${section.id}`}><span>{section.eyebrow}</span>{section.title}</a>)}
          </nav>
          <ButtonLink href="/" variant="quiet">Return to Command Center</ButtonLink>
        </aside>

        <div className="manual-content">
          {visibleSections.length === 0 ? <section className="manual-no-results" role="status"><h2>No matching section</h2><p>Try a broader term such as mission, Guided, evidence, memory, recovery, or System.</p><button type="button" className="os-button os-button--secondary" onClick={() => setQuery("")}>Clear search</button></section> : visibleSections.map((section) => (
            <article className="manual-section" id={section.id} key={section.id} aria-labelledby={`${section.id}-title`}>
              <header><p className="os-eyebrow">{section.eyebrow}</p><h2 id={`${section.id}-title`}>{section.title}</h2><p>{section.summary}</p></header>
              <div className="manual-section-body">{section.content}</div>
              <a className="manual-back-to-top" href="#ti-scale-content">Back to top</a>
            </article>
          ))}
        </div>
      </div>
    </div>
  );
}
