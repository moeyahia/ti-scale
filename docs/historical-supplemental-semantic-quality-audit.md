# Supplemental historical semantic-quality audit

## Decision

The final isolated dry run is acceptable as the reviewed preview for a separate
supplemental execute run. It does not authorize or perform that execute run.

The semantic boundary now keeps broad private source custody while admitting
only narrow reusable knowledge:

- system and developer prompts, token streams, reasoning/control records, and
  incremental model output are rejected;
- provider/model narrative is rejected unless it is an explicit completed tool
  result;
- bare words such as `failed`, `successful`, `reset`, `restart`, or a tool name
  cannot create memory;
- a candidate requires an attributable relationship among a concrete stack or
  version, CVE/applicability, attack vector, tool result, and operational
  observation;
- outcome memory requires an attributable attack result;
- recovery memory additionally requires a failed outcome, a recovery action,
  and an explicit recovery sequence;
- operator-wide Claude, Codex, and Grok archives without a reviewed engagement
  binding remain private custody only and cannot seed reusable memory.

## Reviewed receipt

- Manifest: `deployment/runtime-config/historical-source-roots.supplemental.v2.json`
- Manifest SHA-256:
  `08a2ab9fcead05295f51d0199ec85431d7ef7c14d8b8b52df5199362b6382f5a`
- Dry-run ID: `dry_run_afbc227b-1995-4df4-8fde-526319df6cd8`
- Reconciliation report:
  `/dev/shm/historical-supplemental-quality-final-20260721T144938Z-dry-run/dry_run_afbc227b-1995-4df4-8fde-526319df6cd8/reconciliation.json`
- Report SHA-256:
  `7343169a041823c1cf70012646e47448421f114e7bfce83f910645aca3d4cc7a`
- Inventory receipt SHA-256:
  `4366c3142c9fb246863c408200ada31a373fa3bff70a86a10c94a48f78668ff3`

The receipt completed with `quick_check=ok`, zero foreign-key violations,
zero partial scopes, zero resume cursors, zero automatically verified evidence,
and zero automatically promoted reusable memory.

Three recent source objects (6,667,495 bytes) were explicitly deferred by the
60-second settled-source boundary. They require a later catch-up run after they
are quiescent; they were not silently treated as imported.

## Before and after

| Measure | Initial preview | Final preview | Reduction |
| --- | ---: | ---: | ---: |
| Semantic fact occurrences | 531,600 | 3,999 | 99.25% |
| Connected bundle occurrences | 322,579 | 1,149 | 99.64% |
| Outcome occurrences | 210,946 | 326 | 99.85% |
| Failure-mode occurrences | 145,540 | 283 | 99.81% |
| Recovery occurrences | 67,319 | 108 | 99.84% |
| CVE occurrences | 18,555 | 581 | 96.87% |
| Exact-version occurrences | 11,379 | 771 | 93.22% |
| Tool occurrences | 26,763 | 413 | 98.46% |

Facts per accepted bundle rose from 1.65 to 3.48, consistent with connected
technical relationships replacing isolated status words.

The final generic source boundary contains 569 distinct hash-addressed source
contents across 569 source paths. A separate 22 source-evidence identities came
from the engagement extractor. No semantically accepted path originated from
an unbound operator Claude, Codex, or Grok archive.

Accepted generic semantic source paths were limited to the product runtime:

| Root and source class | Accepted paths | Accepted source bytes |
| --- | ---: | ---: |
| application runtime raw JSONL | 408 | 195,198,433 |
| application runtime structured session JSON | 125 | 8,818,989 |
| orchestration runtime raw JSONL | 34 | 13,089,757 |
| orchestration runtime completed provider/tool JSONL | 2 | 832,764 |

These byte totals identify hash-bound source objects containing at least one
accepted record. They are not claims that every byte is reusable knowledge.

## Classification samples

Deterministic focused fixtures prove the following outcomes:

| Input class | Result | Reason |
| --- | --- | --- |
| Provider stream/token delta containing technical terms | rejected | prompt or stream |
| System/developer example containing a CVE and attack term | rejected | prompt or stream |
| Assistant/model prose claiming an outcome | rejected | non-evidentiary narrative |
| Structured record containing only `failed` and `restart successful` | rejected | insufficient technical context |
| Completed tool output containing an observed Apache version | accepted | evidence-bearing stack fingerprint |
| Structured attack result tied to stack, tool, and failure | accepted | attributable attack result |
| Recovery verb without a failed attributable attack and sequence | rejected as recovery | no causal recovery evidence |

The final receipt recorded the exclusions explicitly, including 3,400 unbound
provider-history sources, 2,331,099 prompt/stream records, 2,088,095 narrative
records, and 38,206 records with insufficient technical context.

## Count semantics and limitation

`semanticFactsParsed` and `connectedBundlesStaged` are occurrence counts, not
unique Brain-node counts. The dry-run compiler intentionally does not persist
candidate identities, so the exact number of distinct normalized candidate
nodes cannot be reconstructed from this receipt without changing the preview
contract and rerunning it. The report does provide exact distinct
hash-addressed semantic source-content identities (569) and exact accepted
bundle occurrences (1,149). No unique-node claim should be made from the 3,999
fact occurrence count.

## Execute acceptance checks

A later execute receipt should be rejected unless all of these remain true:

1. extraction status is `completed`, with zero partial scopes and resume
   cursors;
2. `quick_check` is `ok` and foreign-key violations are zero;
3. evidence automatically verified and memory automatically promoted both
   remain zero;
4. unbound operator provider histories are explicitly skipped and produce zero
   semantic source paths;
5. outcome, failure, and recovery occurrences remain attributable and do not
   return to status-word scale;
6. every recent or active source is explicitly deferred and included in a
   later catch-up receipt rather than silently omitted;
7. source retention remains `verified-reference` and Brain projection remains
   `attack-knowledge-only`.
