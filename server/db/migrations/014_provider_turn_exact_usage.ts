import type { Migration } from "../types";

/**
 * Keep requested-model configuration in `model` while recording the model and
 * exact billing telemetry returned by the provider independently.
 */
export const providerTurnExactUsageMigration: Migration = {
  version: 14,
  name: "provider_turn_exact_usage",
  sql: `
ALTER TABLE provider_turns ADD COLUMN returned_model TEXT
  CHECK (returned_model IS NULL OR (length(returned_model) BETWEEN 1 AND 256));

ALTER TABLE provider_turns ADD COLUMN total_tokens INTEGER
  CHECK (total_tokens IS NULL OR total_tokens >= 0);

ALTER TABLE provider_turns ADD COLUMN billed_cost_usd REAL
  CHECK (billed_cost_usd IS NULL OR billed_cost_usd >= 0);

ALTER TABLE provider_turns ADD COLUMN exact_token_usage INTEGER
  CHECK (exact_token_usage IS NULL OR exact_token_usage IN (0, 1));

ALTER TABLE provider_turns ADD COLUMN exact_cost_usage INTEGER
  CHECK (exact_cost_usage IS NULL OR exact_cost_usage IN (0, 1));
`,
};
