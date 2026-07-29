# Historical attack-knowledge promotion

Historical parsing creates private source-custody evidence candidates and
pending reusable-memory candidates. It does not make those candidates trusted.
The batch promotion gate is the only bounded path intended for homogeneous,
objective historical facts such as exact technology fingerprints, attack
concepts, tool/script hashes, observed outcomes, failure modes, recovery
patterns, and health checks.

The gate excludes target and engagement identifiers, authentication material,
personal preferences, inferred lessons, strategy advice, and unverified CVE or
advisory applicability. Excluded bundles receive durable rejection and
quarantine records. No public language model is used.

Operator confirmation without evidence verification is a separate, hash-bound
workflow. See [Historical memory confirmation](./historical-memory-confirmation.md).

## Preview

```bash
bun run brain:promote-historical -- preview \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --actor operator:local \
  --reason "Approve this exact bounded set of objective, source-backed facts" \
  --max-records 50 \
  --max-bytes 33554432 \
  --max-ms 30000 \
  --dry-run
```

Preview is read-only. Record the returned `previewHash` and inspect every fact,
relationship count, source hash, and rejection category.

## Authorize and run

```bash
bun run brain:promote-historical -- run \
  --db /var/lib/ti-scale/data/ti-scale.sqlite \
  --actor operator:local \
  --reason "Approve this exact bounded set of objective, source-backed facts" \
  --max-records 50 \
  --max-bytes 33554432 \
  --max-ms 30000 \
  --expected-preview-hash <PREVIEW_SHA256> \
  --acknowledge-objective-fact-review
```

Run requires the same server-only HMAC credential used by historical attack
extraction. The service opens each pinned source with `O_NOFOLLOW`, checks the
device, inode, size, and modification time before and after reading, re-hashes
the bytes, and verifies the path still resolves to the same regular inode.

Authorization identity is deterministic from the preview hash. Repeating the
same command resumes pending items or returns `replayed` after completion. A
duration stop returns `partial`; repeat the same command and hash to resume.
When `nextSelectionCursor` is returned, start the next separately reviewed
window by adding `--after <SHA256>` to both preview and run.

Each execution writes an immutable authorization receipt, hash-linked batch
events, standard audit records, item dispositions, and an immutable
reconciliation snapshot with staged, rejected, verified, and promoted counts.
Promotion uses the canonical Attack Knowledge service, so nodes become verified
only with canonical evidence and relationships become real `memory_edges`.
