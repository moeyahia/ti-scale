# Historical residual candidate suppression

Ti-Scale keeps historical confirmation and privacy suppression as separate,
operator-controlled operations. Confirmation turns reviewed reusable knowledge
into visible confirmed memory. This command does the opposite for one narrow
post-import residual class: it removes reusable candidate content whose exact
historical bytes were classified as sensitive and creates a durable
`do-not-relearn` suppression.

This command is not part of normal import and it does not confirm, reject, or
classify general historical knowledge. Run it only after the configured import,
catch-up scan, supplemental-source scan, and confirmation passes have completed.
Waiting until then lets a later safe copy corroborate and rescue a candidate.

## Eligibility boundary

A candidate is eligible only when all of these statements remain true in the
same database transaction that performs the write:

- it is an unmaterialized, pending `attack-knowledge-compiler` candidate;
- every compiler source binding has a matching historical source occurrence;
- every exact origin hash has at least one completed, receipt-backed migration
  using `verified-reference` retention and `attack-knowledge-only` projection;
- those completed source objects are quarantined as `sensitive_content`;
- every other terminal inventory classification for those hashes is also
  `quarantined/sensitive_content`;
- no completed accepted source, current-runtime receipt, active migration,
  receiptless historical binding, or nonterminal standalone occurrence exists.

Failed-only custody is not sufficient. A source classified as accepted by any
completed migration makes the candidate ineligible. If that corroboration
appears after preview, execution fails as stale without suppressing anything.

## Preview

```bash
bun run brain:suppress-historical-residuals -- preview \
  --db /absolute/path/to/ti-scale.sqlite \
  --actor operator:memory-review \
  --reason "Remove only residual candidates with exclusively sensitive quarantine custody." \
  --dry-run \
  --max-candidates 250
```

The preview is read-only. It returns candidate IDs, reusable-content
fingerprints, node types, aggregate custody counts, and non-reversible custody
set hashes. It deliberately omits source paths, raw source hashes, titles,
summaries, bodies, labels, and private payloads.

Review the page and retain its exact `previewHash`. A page is bounded to at most
1,000 candidates. Continue with `--after <nextSelectionCursor>` only after the
current page has been executed and receipted.

## Execute

```bash
bun run brain:suppress-historical-residuals -- run \
  --db /absolute/path/to/ti-scale.sqlite \
  --actor operator:memory-review \
  --reason "Remove only residual candidates with exclusively sensitive quarantine custody." \
  --expected-preview-hash <64-character-preview-hash> \
  --acknowledge-suppress-sensitive-residuals \
  --receipt /secure/operator-receipts/residual-page-001.json \
  --max-candidates 250
```

Execution acquires the canonical database writer lease, opens an immediate
transaction, re-evaluates the complete eligibility boundary, verifies the
lease fence, and requires an exact preview match. For each reviewed candidate
it then:

1. hashes the original candidate content for the suppression key;
2. inserts a scoped `memory_suppressions` do-not-relearn record;
3. changes the candidate state to `suppressed`;
4. removes title, summary, body, confidence, and source payload content;
5. appends the existing per-candidate operator audit record.

The service finally appends one privacy-safe aggregate audit record and writes
an atomic mode-`0600` CLI receipt. The receipt binds the preview, selected set,
private custody set, counts, page cursor, actor, time, and policy version without
disclosing the sensitive origins. Repeating the exact acknowledged execution
replays the existing aggregate receipt and does not write duplicate
suppressions.

## Failure behavior

The operation fails closed when:

- the canonical custody or lease schema is unavailable;
- the acknowledgement or exact preview hash is missing;
- the page is empty;
- source inventory or candidate state changed after preview;
- a safe completed occurrence now corroborates the source;
- a source is still being imported;
- a historical receipt is not bound to an occurrence;
- the writer lease is absent, expired, or fenced out;
- an earlier aggregate receipt fails its hash check.

No partial page is committed: candidate suppressions and the aggregate audit
record share one transaction.

## Verification

After the final page, regenerate the preview from the beginning. It should be
empty. Separately verify that no confirmed memory was affected and that no
accepted source hash was suppressed:

```sql
SELECT status, COUNT(*)
FROM memory_candidates
GROUP BY status;

SELECT COUNT(*) AS aggregate_receipts
FROM audit_records
WHERE action = 'historical_residual_candidates.suppressed';

SELECT COUNT(*) AS suppressions
FROM memory_suppressions;
```

The original historical source inventory and quarantine custody remain intact
for audit. This workflow removes only reusable candidate payloads; it does not
delete immutable evidence, engagement logs, migration inventories, or audit
history.
