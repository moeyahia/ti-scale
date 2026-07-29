# Ti-Scale Project Goal

## Authoritative outcome

Complete Ti-Scale as a standalone, functional product and activate the completed
application as the current Ti-Scale service on port `3132`. The next deployment
replaces the older Ti-Scale build; it is not another disposable or
operator-invisible preview.

Every unrelated application and service is outside this workstream and must
remain untouched.

## Immediate completion target

The active Ti-Scale application must provide one coherent operator-visible
Autonomous journey:

1. create an authorized mission with understandable defaults;
2. build and display the editable plan;
3. route work to the configured specialist agents and their pinned models;
4. execute every installed, supported tool binding that the mission authorizes;
5. show live progress, meaningful logs, failures, and recovery;
6. retain custody-complete evidence and evidence-backed findings;
7. persist the evaluation and produce downloadable reports;
8. write reusable, target-independent attack knowledge through the Second Brain;
9. project connected, valid Markdown and wikilinks into the active Obsidian
   Vault; and
10. make the completed result inspectable from the mission, Agents, Evidence,
    Reports, Brain, and Vault interfaces.

## Development priorities

- Product completion and operator-visible functionality take priority over
  release-certification ceremony.
- Installed and supported capabilities must be connected and usable rather than
  hidden behind artificial readiness states.
- Provider, model, fallback, reasoning, enforcement, and disclosure settings
  must be configurable and inspectable per agent.
- The active Brain/Vault integration must be used by the runtime, not populated
  only by manual or fixture-only operations.
- Development work must not be diverted into unrelated products or services
  unless the operator explicitly expands the task.
- The operator has requested a no-backup, forward-only Ti-Scale update.

## Functional invariants

The following are runtime correctness requirements, not reasons to leave
features unavailable:

- actions remain bound to the mission's authorized targets and represented
  parameters;
- credentials and secrets are not written into reusable memory or disclosed to
  an unauthorized provider;
- verified claims retain attributable evidence and custody;
- cancellation, retry, and loop bounds prevent orphaned or endlessly repeating
  work.

## Deployment target

- Active Ti-Scale application: `http://127.0.0.1:3132`
- Update mode: forward-only and no retained backup or rollback payload

## Continuity rule

After context compaction, restart, or delegation, continue from the current
Ti-Scale source and deployed state. Do not restart from an audit, revert to a
preview-only or cutover-closed objective, or divert into another product unless
the operator explicitly changes this goal. This document supersedes stale
thread-goal metadata for Ti-Scale work.
