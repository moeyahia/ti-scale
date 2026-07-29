# Attack Knowledge Vault

Ti-Scale's reusable Vault is organized around **technology, attack applicability, outcomes, and safe repetition**. It is not an archive of box names, IP addresses, mission journeys, or chat transcripts.

## Governing invariant

The transactional database and the reusable Vault serve different purposes:

- The private engagement record retains authorization, scope, target identity, immutable evidence, and audit history where policy requires it.
- The Attack Knowledge Vault stores sanitized, reusable knowledge that can improve work against a different authorized target with a matching technology stack.

Target names, IP addresses, CIDRs, domains, URLs, client names, journey labels, control-plane details, credentials, secrets, raw logs, and raw evidence are not projected into reusable notes. A reusable note may hold an opaque private provenance receipt so an authorized operator can trace it back without disclosing target identity to retrieval or public providers.

## Reusable taxonomy

The authoritative type-to-folder and type-to-Brain-region mapping lives in
`shared/AttackBrainAtlasMappingRegistry.ts`. Server projection, YAML
`brain_region`, the generated Brain Atlas profile, and the browser renderer all
consume that registry. A type cannot be added to reusable attack memory unless
the completeness test assigns it exactly once.

```text
00 Inbox/
10 Operator/                  # optional explicit Operator Profile projection
20 Technology Products/
21 Versions and Fingerprints/
22 Software Stacks/
23 Security Controls/
30 Topology Patterns/
40 Vulnerabilities and Weaknesses/
41 Attack Vectors/
42 Techniques and Procedures/
43 Prerequisites and Attributes/
44 Discovery and Fingerprints/
45 Scripts and Tools/
50 Outcomes and Validation/
51 Operational Hazards/
52 Recovery and Alternatives/
53 Detection and Remediation/
60 Strategies and Lessons/
61 Research/
Attachments/
```

Mission, run, report, and target folders do not belong in this reusable
projection. `10 Operator` is present only when the separately reviewed,
explicit-consent Operator Profile scope is enabled; it is not attack evidence.

## Dedicated Obsidian connection preset

The product setup screen provides one recommended **Ti-Scale Attack Knowledge
Vault** preset. Its relative path is `Attack-Knowledge-Vault` inside the
server-owned `TI_SCALE_VAULT_ROOT` sandbox. Previewing the preset is read-only:
it does not create a directory, insert a connection, export a note, or alter an
existing vault.

The default projection policy is fixed and inspectable:

- node types come only from the canonical reusable attack-knowledge registry;
- scope is global only, with no engagement or mission identifiers;
- lifecycle is verified only;
- public, internal, and private generalized knowledge may be projected;
- restricted memory is withheld;
- target, mission, run, plan, step, evidence, finding, artifact, report, and
  source nodes are excluded;
- the attack-centric folder taxonomy above is created empty at activation;
  notes are written only by a later explicit export or synchronization action.

Including operator-confirmed knowledge is a separate, visible opt-in. It changes
the policy hash and therefore requires a fresh preview and activation review.
It is never inferred from a generic memory-control setting.

When the verified-only preset is already connected, this opt-in is applied as
an audited **in-place scope amendment**, not as a second connection. The request
is bound to the existing connection ID and version, the exact current and target
policy hashes, a fresh round-trip proof on the existing path, an explicit
acknowledgement, and an operator-attributed reason. A stale version or policy
fails closed. The amendment retains the Vault path, notes, synchronization
history, and conflicts, and writes or deletes zero notes. A later explicit
export performs the incremental Markdown projection.

### Optional Operator Profile category

Confirmed attack knowledge and confirmed operator preferences are different
data classes. Enabling the first never silently enables the second. An existing
verified-plus-confirmed Attack Knowledge Vault therefore requires one further,
explicit **Operator Profile scope amendment** before `10 Operator` notes may be
projected.

The target policy is an exact third preset variant:

- the same Vault connection ID and filesystem path are retained;
- lifecycle remains `verified + confirmed`;
- the custom scope marker is exactly
  `explicit_operator_preferences_v1`;
- the authenticated operator ID is part of the reviewed sync scope and policy
  hash, so one operator's profile cannot be selected by another operator's
  amendment;
- only the canonical Operator root, explicit-consent confirmed preferences,
  and their finite manifest-owned applicability-domain nodes qualify;
- an arbitrary `operator`, `preference`, or `entity` node does not qualify;
- engagement, mission, target, IP, hostname, URL, evidence, and artifact nodes
  remain excluded;
- restricted content remains excluded;
- a generic Vault connection cannot opt into this projection by listing broad
  node types.

Eligibility is checked against `preference_profiles` with
`confirmation_state = confirmed` and
`consent_policy = explicit_operator_confirmation`, plus the confirmed,
operator-authored `prefers` and `applies_to` graph. Applicability-domain nodes
must also retain their `operator_instruction_manifest` provenance. This makes
the native Obsidian links truthful without admitting unrelated operational
entities.

The amendment is bound to the current connection version, the exact current
and target policy hashes, a fresh existing-path round trip, an attributable
reason, and an explicit Operator Profile acknowledgement. It creates the empty
`10 Operator` directory if required, appends the tamper-evident
`vault.attack_knowledge_preset.operator_profile_scope_amended` audit record,
and writes or deletes zero notes. A separate explicit export or synchronization
operation projects the canonical notes and their `[[wikilinks]]`.

Activation requires all of the following:

1. access to reusable global knowledge;
2. explicit filesystem permission for the preset path;
3. an explicit activation acknowledgement;
4. the exact SHA-256 policy hash returned by the current preview;
5. a fresh write, read, rename, and delete round-trip inside the preset path;
6. an idempotency key and an attributable audit record.

The preset name and path are reserved. The generic custom-vault endpoint cannot
use either to create a broader look-alike connection. Activation does not
disconnect, delete, import, migrate, or modify any other configured vault.

## Canonical reusable nodes

The reusable graph includes, where supported by evidence:

- technology, product, component, version constraint, CPE, package, operating system, kernel, framework, runtime, database, service, and protocol;
- firewall, WAF, proxy, EDR, authentication layer, and other security controls identified by product and version rather than address;
- address-free topology patterns and trust/reachability relationships;
- CVEs, advisories, CWEs, weaknesses, misconfigurations, and applicability claims;
- attack vectors, techniques, procedures, prerequisites, attributes, ordered steps, and safe operating bounds;
- scripts, tools, parameterized command patterns, tests, hashes, inputs, outputs, side effects, cleanup, and validation rules;
- discovery and fingerprint patterns;
- verified success, failure, partial outcome, operational hazard, target state, recovery, alternative, detection, and remediation patterns;
- strategies, verified lessons, experiments, and benchmark results.

Every node records provenance, confidence, lifecycle, sensitivity, version, freshness, applicability constraints, and disclosure class. Verification and permission to disclose to a public provider remain separate decisions.

Reusable tactic, technique, procedure, and lesson records use dedicated `attack_tactic`, `attack_technique`, `attack_procedure`, and `attack_lesson` node types. Historical generic records do not become cross-engagement knowledge merely because they have a similar label.

## Relationships

The graph uses evidence-backed typed relationships. Important examples from the
canonical registry include:

- `has_exact_version`, `has_version_range`, `version_in_range`, `runs_on`,
  `built_with`, `uses_runtime`, `uses_database`, `protected_by`, and
  `has_topology_role` for stack composition;
- `affects`, `classified_as`, `applicable_to`, and `not_applicable_to` for
  vulnerability matching;
- `exploits`, `requires`, `has_attribute`, `tested_against`, and `bypasses` for
  attack applicability;
- `implemented_by`, `discovered_by`, `fingerprinted_by`,
  `matches_fingerprint`, and `validated_by` for procedures, discovery, and
  artifacts;
- `produces_outcome` and `failed_because` for outcomes;
- `caused`, `leaves_in_state`, `avoid_after`, `safe_when`, and `requires_recovery` for operational hazards;
- `recovered_with`, `alternative_to`, `mitigated_by`, `detected_by`, and
  `remediated_by` for safe adaptation;
- `supports`, `contradicts`, `supersedes`, and `derived_from` for knowledge
  quality.

An edge is never generated merely to make the graph look connected. It must carry the evidence, inference category, confidence, and provenance that justify it.

## Stateful failure and operational-hazard memory

A failed command is not enough. Ti-Scale must record what state the target entered and why repeating the same sequence may be harmful or wasteful.

An `operational_hazard` record includes:

- affected product/component and exact or bounded version applicability;
- relevant OS, kernel, framework, runtime, database, topology, and security-control constraints;
- vector, technique, procedure version, script hash, and ordered step sequence;
- normalized parameter bounds such as request count, payload size, concurrency, delay, timeout, and retry cadence;
- required preconditions and target state before execution;
- expected state transition and the state actually observed;
- symptoms and health signals, including timeouts, queue saturation, process deadlock, service degradation, or a non-responsive application path;
- attempts, repeated occurrences, resets required, reproducibility, confidence, and counterexamples;
- affected component, blast radius, reversibility, reset cost, and artifacts preserved;
- unsafe retry conditions and a precise `do not retry until` health gate;
- recovery procedure, proof of recovery, safer sequence, and alternative technique;
- freshness, expiry/review date, evidence references, and opaque private source receipts.

The supervisor consults matching hazard memory before a retry, replan, or equivalent attack attempt. When the stack and preconditions match, it must surface the risk, run the recorded health gate, respect the safe retry bound, and prefer a verified safer sequence. It must not blindly repeat the action because a prior run used a different target identity.

Reset accounting deliberately has two independent values. The exact-procedure
count includes only resets attributable to the same reviewed procedure version,
parameters, prerequisites, and state transition. A separately labelled
operator-reported minimum captures the broader recovery burden when several
different attack paths contributed to target resets. The aggregate is useful
for risk and planning, but it is never presented as proof that one procedure
caused every reset.

### Continuous hang and reset capture

Future reset episodes enter reusable learning only through a canonical,
append-only observation path:

1. Preserve the failed or safely aborted `AttackAttempt`, including its exact
   procedure/version binding, normalized parameters, prerequisites, target
   state, and canonical target context.
2. Before dispatch, issue one expiring, server-HMAC-authenticated reset
   authorization bound to the canonical action, failed attempt, and private
   target-context fingerprint. It is one-use and cannot be supplied by a
   provider, tool result, or browser request.
3. Represent the recovery as one succeeded `target_reset` or
   `environment_reset` action bound to that authorization and failed attempt.
   A generic tool success or chat statement is not a reset receipt.
4. Retain distinct, locally generated pre-reset and post-reset health results.
   The first must prove the affected baseline was not healthy; the second must
   prove both that the reset completed and that the baseline was restored.
5. Require the trusted local reset controller to authenticate its physical
   reset operation and resulting target generation for that exact action. A
   fresh but unsigned operation identifier is rejected, not merely deduplicated.
6. The fixed local evaluator produces one immutable `target_reset_result`
   evidence record and verification custody for that exact action, attempt,
   and private target-context fingerprint. Operator prose and public-model
   output cannot serve as this proof.
7. The durable observation worker converts the unique physical occurrence into
   a sanitized candidate bundle. A recovery action and recovery event can each
   increment the exact count only once, including after worker restart.
8. The candidate remains pending until an authenticated operator reviews and
   promotes its exact generalized diff. Observation never auto-promotes or
   silently changes a running strategy.

The server-only HMAC key is loaded from
`TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE` (preferred managed credential),
`TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY`, or a mode-`0600` companion file beside
the canonical database for a standalone local installation. This installation
does not create a backup of that key. Rotating or losing it intentionally
makes prior reset authorizations and receipts unverifiable rather than
silently trusting them.
The key file and its containing directory must never be mounted into a tool,
provider, browser, or public-model sandbox, and the key variable must be
removed from every child-process environment. A reset adapter receives only a
bounded attestation capability; general execution tools never receive the raw
key.

An operator may also record an engagement-wide lower bound such as “more than
ten resets.” This is stored as a monotonic aggregate minimum (`11` in that
example). It is never summed and never assigned to a procedure without exact
attribution evidence. Each procedure view therefore reports its exact reset
count, the overall minimum, and the portion of that minimum not tied to that
procedure. A source-level reconciliation report separately computes the
minimum still unattributed after all distinct exact receipts are considered.

A health gate is a first-class operational assessment, not a checked box or a
free-text acknowledgement. Its pass record must bind the hazard, exact
procedure and procedure version, private target-context fingerprint,
represented health-check action, immutable evidence, evaluator version,
Context Pack, expiry, and the new attempt it authorizes. A pass restores a
known-good baseline; it does **not** make the identical known-bad procedure
safe. Continuation still requires the recorded safer procedure version,
parameter exclusions, bounded attempt count, or alternative technique. Gate
records cannot be reused across targets, environments, or expired state.

### Repeated application-hang transformation example

The source engagement may record that a named lab box required more than ten
resets. The reusable note does **not** retain the box name or address. Distinct
procedures are not merged merely because they caused the same reset. For
example, one corroborated application-path pattern becomes:

```text
Affected stack:
  Microsoft IIS 10 + ASP.NET WebForms hosting an embedded d8 12.2 execution path
  Windows build 20348 family, constrained to corroborated patch evidence

Procedure:
  one bounded CVE-2024-2887 validation stage / exact procedure version / script hash

Observed transition:
  application probe passes -> one long-running expression is submitted ->
  expression POST stops responding while the base page remains reachable

Reproducibility:
  count only corroborated attempts for this exact procedure; retain the
  operator-reported aggregate reset count separately as recovery cost

Unsafe retry rule:
  do not repeat this procedure, or advance to the next stage, while the minimal
  application execution probe fails; a reachable base page is not sufficient

Safe sequence:
  establish baseline -> prove the execution probe -> run one bounded stage with
  zero automatic retries -> repeat the execution probe -> checkpoint -> continue once

Recovery:
  recycle or reset the affected execution component, prove the execution probe
  passes, exclude the known-bad parameter family, and resume from the last safe checkpoint
```

This knowledge can then protect a different authorized target that presents the same stack, state, and prerequisites.

## Generalization rules

Before projection, the knowledge compiler transforms source-specific data:

- IP address or hostname becomes an address-free topology role.
- A concrete URL becomes a parameterized endpoint pattern only when it is material to the technique.
- Credentials become an authentication class or prerequisite; credential material is never retained.
- A target or engagement identifier becomes a private opaque provenance receipt.
- Journey and control-plane labels are discarded from reusable knowledge.
- Timestamps are retained only as freshness, ordering, or applicability signals.
- Raw evidence remains in the immutable evidence store and is referenced by protected ID.

The compiler quarantines a candidate when it cannot reliably remove target identity, secret-bearing content, prompt-injection content, or unsupported inference.

## Deduplication and knowledge identity

Reusable knowledge is deduplicated by a stable fingerprint derived from:

```text
product/component identity
+ version constraint or CPE/package range
+ OS/kernel/runtime constraint
+ vector and technique
+ normalized prerequisites and ordered procedure
+ topology pattern
+ security-control product/version constraints
+ target-state transition
```

New observations add evidence, counterexamples, version bounds, and outcome statistics to the same pattern instead of creating one note per target.

## Matching and retrieval

For a newly discovered authorized target, retrieval follows this order:

1. Normalize the observed product, versions, CPE/package data, OS/kernel/runtime, services, topology, and security controls.
2. Match version and applicability ranges without treating an unverified banner as proof.
3. Require the procedure's prerequisites, topology, and security-control conditions.
4. Retrieve verified successes, failures, operational hazards, recoveries, and counterexamples together.
5. Reject stale, contradicted, cross-engagement-restricted, or disclosure-ineligible knowledge.
6. Rank by applicability confidence, evidence strength, repeated outcomes, freshness, safety, and prior usefulness.
7. Produce a bounded Context Pack that explains why each pattern matched and how it changes the plan.

A high-confidence hazard can veto an automatic retry or require an explicit health gate. A remembered success never expands authorization or bypasses current policy.

## Reuse-value gate

A retained record is not valuable merely because it says that an action failed or
that an environment was reset. Before it can become verified reusable knowledge,
it must let a future planner answer all of these questions without knowing the
original target identity:

1. Which product, component, exact version or bounded version range, runtime,
   kernel, topology role, and security control made the observation applicable?
2. Which exact procedure version, script or tool hash, ordered steps, parameters,
   concurrency, timing, and prerequisites produced the outcome?
3. What healthy baseline was proven before execution, what observable state
   transition occurred, and which components remained healthy?
4. Was the outcome successful, partial, failed, or hazardous, and which immutable
   evidence supports that classification?
5. How many attempts and resets are attributable to this exact procedure, and
   which broader recovery totals remain unattributed?
6. Which condition makes repetition unsafe, which health check restores a known
   baseline, and which materially different procedure or parameter set is safer?
7. What would make a future retry valid, and what must cause it to stop without
   another automatic attempt?

If one of these answers is missing, Ti-Scale may surface the record as a warning
or review candidate, but it cannot use it as a verified execution gate or claim
that the lesson applies to another environment. Target names, addresses, mission
journeys, and chat wording never satisfy this gate.

## Historical evidence boundary

Private historical records enter this system only through the [bounded historical hazard importer](./historical-hazard-import.md). The importer stages canonical artifacts and evidence candidates, but cannot verify evidence or promote memory. After independent review, its immutable bundle link records the exact compiler provenance receipt, derived source-set hash, and sorted canonical evidence IDs. Promotion can therefore validate the exact private evidence set without placing mission, target, address, journey, or source-path data in reusable nodes.

## Acceptance criteria

The Attack Knowledge Vault is not complete until:

- target names and addresses are absent from reusable projections;
- one technique observed on many targets consolidates into reusable, evidence-weighted knowledge;
- version ranges, prerequisites, topology, and controls determine applicability;
- worked, failed, partial, hazardous, and recovery outcomes remain distinct;
- repeated target hangs produce a pre-execution warning, retry bound, health gate, and safer alternative on a matching future stack;
- every recommendation can show its memory path and protected provenance;
- a forgotten source is removed from derived counts, edges, cached retrieval, and synchronized notes;
- public providers receive only disclosure-approved sanitized Context Pack items;
- the graph and Obsidian projection contain only real, supported relationships.
