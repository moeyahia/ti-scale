# Historical operational-hazard evidence import

Ti-Scale can turn a small, deliberately selected set of private historical files into reviewable operational-hazard knowledge without scanning an entire engagement tree and without promoting raw records as trusted memory.

The trust sequence is deliberately split:

1. An operator creates a bounded manifest containing 1–64 exact files, SHA-256 hashes, sizes, timestamps, containment roots, private labels, and intended evidence classes.
2. `hazard-preview` reopens and hashes only those files. It returns a deterministic preview hash and performs no filesystem or database writes.
3. `hazard-stage` requires that exact preview hash and explicit operator approval. Each source remains in place behind an exact verified reference and becomes one private canonical artifact plus one `candidate` evidence record.
4. A different authorized reviewer uses the normal Intelligence evidence workflow to validate source authenticity, hazard attribution, provenance, and custody. The importer cannot perform this step.
5. `hazard-bind-preview` accepts only verified evidence produced from candidates in the same import job. It previews the exact reusable graph and evidence set.
6. `hazard-bind` requires the exact binding preview hash and a second operator approval. It stages reusable memory candidates; it does not confirm or verify them.
7. The normal Attack Knowledge promotion review verifies the reusable nodes, edges, and evidence-bound receipt.

A source file, command transcript, or operator statement therefore never becomes verified evidence merely because it was imported.

## Bounded source manifest

```json
{
  "schemaVersion": 1,
  "missionId": "mission-imported-private-history",
  "runId": "run-imported-private-history",
  "privateLabels": ["private engagement label", "private target label"],
  "sources": [
    {
      "selectionId": "bounded-procedure-script",
      "absolutePath": "/private/history/scripts/bounded-procedure.js",
      "containmentRoot": "/private/history",
      "sha256": "<64-character sha256>",
      "byteSize": 4096,
      "modifiedAt": "2026-07-20T00:00:00.000Z",
      "evidenceType": "generated_script_source",
      "label": "Reviewed bounded procedure source",
      "meaning": "May prove the exact implementation used by the historical procedure",
      "mediaType": "text/javascript"
    }
  ]
}
```

The manifest is the complete discovery boundary. The importer never walks sibling files or rescans the parent tree. Each source is reopened with no-follow semantics and must still match its reviewed inode metadata, size, timestamp, and SHA-256 before recording the reference. Resume revalidates only pending source items.

Private labels are stored only as hashes in the canonical database. The original labels remain in the protected private manifest and must be supplied again during binding so the reusable-memory leak scanner can reject engagement names, target labels, addresses, filesystem paths, credentials, and other operational locators.

## Commands

```bash
bun run hazard:import:preview \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --manifest /private/review/hazard-manifest.json

bun run hazard:import:stage \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --manifest /private/review/hazard-manifest.json \
  --preview-hash <reviewed-preview-hash> \
  --approved-by <operator-id> \
  --approve-stage

bun run hazard:import:reconcile \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --job <job-id>
```

After every selected candidate has been independently verified, create a sanitized knowledge JSON document and preview the exact binding:

```bash
bun run hazard:knowledge:preview \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --job <job-id> \
  --knowledge /private/review/sanitized-hazard-knowledge.json \
  --evidence <verified-evidence-id> \
  --private-label '<original private engagement label>' \
  --private-label '<original private target label>'

bun run hazard:knowledge:stage \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --job <job-id> \
  --knowledge /private/review/sanitized-hazard-knowledge.json \
  --evidence <verified-evidence-id> \
  --private-label '<original private engagement label>' \
  --private-label '<original private target label>' \
  --binding-preview-hash <reviewed-binding-hash> \
  --approved-by <operator-id> \
  --approve-binding
```

Binding commands require an existing server-only `TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY` or mode-private `TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE`. The CLI never creates a new key during a dry run.

## Reusable hazard shape

The sanitized knowledge document can preserve:

- exact product, framework, runtime, operating-system, kernel, proxy, firewall, WAF, and security-control versions;
- exact procedure version, ordered steps, normalized bounded parameters, and preconditions;
- reusable script name, version, SHA-256, language, and purpose;
- evidence-backed discoveries;
- explicit worked and failed outcomes and their reusable failure mechanisms;
- the stall signature, before/after state, affected component, unaffected components, and surviving health signals;
- exact attributed reset count, separately labeled operator-reported aggregate reset minimum, and other recovery cost;
- conditions that make another retry unsafe and conditions that make one distinct safer retry valid;
- harmless health gates and the distinct safer sequence.

Script, discovery, and outcome records must each cite a content hash present in the selected canonical evidence set. The compiler stages `script_artifact`, `discovery_pattern`, `outcome`, `failure_mode`, `attribute`, and `health_check` candidates and connects them using typed relationships including `implemented_by`, `tested_against`, `produces_outcome`, `failed_because`, `safe_when`, and `recovered_with`.

The reusable graph excludes mission IDs, run IDs, target names, addresses, engagement names, journey labels, source paths, transcripts, and credentials. Those remain only in private canonical artifacts/evidence and verified-reference provenance.

## Reconciliation and recovery

`hazard-reconcile` reports source count and bytes, durable checkpoint, candidate states, independently verified evidence count, artifact/hash/link mismatches, staged bundle ID, and a deterministic reconciliation hash. Staging is idempotent. An interrupted job resumes from its last source checkpoint without duplicating artifacts or candidates. A completed job replays its existing result.

No command in this workflow deploys code, changes a live mission, verifies evidence automatically, confirms memory, or promotes a knowledge bundle.
The CLI rejects `--backup-root`; no source copy, database copy, archive, or
rollback payload is created.
