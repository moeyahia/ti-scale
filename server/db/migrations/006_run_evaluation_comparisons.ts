import type { Migration } from "../types";

export const runEvaluationComparisonsMigration: Migration = {
  version: 6,
  name: "canonical_run_evaluation_comparisons",
  sql: String.raw`
CREATE TABLE run_evaluation_comparisons (
  evaluation_id TEXT PRIMARY KEY REFERENCES run_evaluations(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL UNIQUE REFERENCES runs(id) ON DELETE CASCADE,
  comparison_status TEXT NOT NULL CHECK (comparison_status IN ('available', 'insufficient_data')),
  basis TEXT CHECK (basis IS NULL OR basis IN (
    'same_mission_and_journey', 'same_engagement_and_journey'
  )),
  reason TEXT NOT NULL,
  prior_evaluation_id TEXT REFERENCES run_evaluations(id) ON DELETE RESTRICT,
  prior_run_id TEXT REFERENCES runs(id) ON DELETE RESTRICT,
  prior_terminal_status TEXT CHECK (
    prior_terminal_status IS NULL OR prior_terminal_status IN ('completed', 'failed', 'cancelled')
  ),
  terminal_status_match INTEGER CHECK (terminal_status_match IS NULL OR terminal_status_match IN (0, 1)),
  metrics_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(metrics_json) AND json_type(metrics_json) = 'array'),
  summary TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (
    comparison_status = 'insufficient_data' OR (
      basis IS NOT NULL AND prior_evaluation_id IS NOT NULL AND prior_run_id IS NOT NULL
      AND prior_terminal_status IS NOT NULL AND terminal_status_match IS NOT NULL
      AND json_array_length(metrics_json) > 0
    )
  )
) STRICT;

CREATE INDEX idx_run_evaluation_comparisons_prior
  ON run_evaluation_comparisons(prior_evaluation_id, created_at);

CREATE TRIGGER run_evaluation_comparisons_immutable_update
BEFORE UPDATE ON run_evaluation_comparisons
BEGIN
  SELECT RAISE(ABORT, 'run evaluation comparisons are immutable');
END;

CREATE TRIGGER run_evaluation_comparisons_immutable_delete
BEFORE DELETE ON run_evaluation_comparisons
WHEN OLD.reason != 'legacy_evaluation_not_compared'
BEGIN
  SELECT RAISE(ABORT, 'run evaluation comparisons are immutable');
END;

INSERT INTO run_evaluation_comparisons (
  evaluation_id, run_id, comparison_status, basis, reason, prior_evaluation_id,
  prior_run_id, prior_terminal_status, terminal_status_match, metrics_json,
  summary, created_at
)
SELECT re.id, re.run_id, 'insufficient_data', NULL, 'legacy_evaluation_not_compared',
  NULL, NULL, NULL, NULL, '[]',
  'Insufficient comparable data: this legacy evaluation predates canonical run comparison.',
  re.created_at
FROM run_evaluations re
WHERE NOT EXISTS (
  SELECT 1 FROM run_evaluation_comparisons rec WHERE rec.evaluation_id = re.id
);
`,
};
