# Ti-Scale Working Instructions

Read and follow [`docs/project-goal.md`](docs/project-goal.md) before planning,
editing, testing, or deploying Ti-Scale.

The host-level operational methodology is `/root/AGENTS.md`. Its approved
SHA-256 at this checkpoint is
`8a83e8996bf00833997df96cb26050a5fa132f3d9c0002cea4ab13b2ed4c0606`.
Read it before runtime, tool, engagement, or agent-orchestration work. Treat a
missing file or checksum mismatch as an explicit continuity defect; do not
silently replace the Kali-native methodology with wrapper-only behavior.

## Persistence and precedence

These files are the durable source of truth for ongoing Ti-Scale work:

1. this file for repository-specific working instructions; and
2. `docs/project-goal.md` for the current product and deployment outcome.

They must be read after context compaction and by every sub-agent. The
standalone, forward-only Ti-Scale completion objective below supersedes older
conversation or thread-goal wording that describes Ti-Scale as a preview or
requires keeping its cutover closed.

The operator's current objective is to finish the actual standalone Ti-Scale
product and activate the completed build as the current service on port `3132`;
do not substitute another disposable or operator-invisible preview.

Keep every unrelated application and service outside this workstream unless the
operator explicitly expands the Ti-Scale task.

Prioritize coherent operator-visible functionality:

- complete Autonomous execution from intake through tools, evidence,
  evaluation, reports, Brain, and Vault;
- connect installed supported tools and canonical specialist agents;
- expose real per-agent provider/model configuration;
- use the connected Obsidian Vault through the runtime;
- deploy forward-only without retained backup or rollback payloads, as requested.

Do not use release-certification ceremony as a reason to leave product
functionality unfinished or hidden. Preserve the runtime correctness invariants
listed in `docs/project-goal.md`.
