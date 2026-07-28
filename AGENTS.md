# Ti-Scale Working Instructions

Read and follow [`docs/project-goal.md`](docs/project-goal.md) before planning,
editing, testing, or deploying Ti-Scale.

The operator's current objective is to finish the actual standalone Ti-Scale
product and activate the completed build as the current service on port `3132`;
do not substitute another disposable or operator-invisible preview.

Keep ChillsPwn on port `3131` outside this workstream unless the operator
explicitly opens a separate ChillsPwn task.

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
