import type { Migration } from "../types";

/**
 * One Autonomous activation receipt joins the signed contract to the exact
 * runtime generation, Brain Context Pack, one run-level planning selection,
 * execution assignments, tools, and evidence-producing routes that were ready
 * at launch. Receipt headers and route items are immutable. Later planning,
 * dispatch, resume, and restart consumers append hash-chained bindings rather
 * than rewriting that authority.
 */
export const autonomousActivationReceiptsMigration: Migration = {
  version: 58,
  name: "autonomous_activation_receipts",
  sql: String.raw`
CREATE TABLE autonomous_activation_receipts (
  id TEXT PRIMARY KEY,
  schema_version TEXT NOT NULL CHECK (schema_version = '2.4'),
  mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE RESTRICT,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
  contract_id TEXT NOT NULL REFERENCES mission_contracts(id) ON DELETE RESTRICT,
  generation INTEGER NOT NULL CHECK (generation > 0),
  contract_version INTEGER NOT NULL CHECK (contract_version > 0),
  contract_hash TEXT NOT NULL CHECK (
    length(contract_hash) = 64 AND contract_hash NOT GLOB '*[^0-9a-f]*'
  ),
  runtime_generation_hash TEXT NOT NULL CHECK (
    length(runtime_generation_hash) = 64
    AND runtime_generation_hash NOT GLOB '*[^0-9a-f]*'
  ),
  planning_route TEXT NOT NULL CHECK (
    planning_route IN ('local_deterministic', 'provider_advisory')
  ),
  planning_selection_json TEXT NOT NULL CHECK (
    json_valid(planning_selection_json)
    AND json_type(planning_selection_json) = 'object'
  ),
  planning_selection_hash TEXT NOT NULL CHECK (
    length(planning_selection_hash) = 64
    AND planning_selection_hash NOT GLOB '*[^0-9a-f]*'
  ),
  planning_planner_id TEXT NOT NULL CHECK (
    length(trim(planning_planner_id)) > 0
  ),
  planning_model_assignment_id TEXT
    REFERENCES agent_model_assignments(id) ON DELETE RESTRICT,
  planning_primary_configuration_id TEXT
    REFERENCES model_configurations(id) ON DELETE RESTRICT,
  planning_fallback_configuration_id TEXT
    REFERENCES model_configurations(id) ON DELETE RESTRICT,
  planning_primary_configuration_hash TEXT CHECK (
    planning_primary_configuration_hash IS NULL
    OR (
      length(planning_primary_configuration_hash) = 64
      AND planning_primary_configuration_hash NOT GLOB '*[^0-9a-f]*'
    )
  ),
  planning_fallback_configuration_hash TEXT CHECK (
    planning_fallback_configuration_hash IS NULL
    OR (
      length(planning_fallback_configuration_hash) = 64
      AND planning_fallback_configuration_hash NOT GLOB '*[^0-9a-f]*'
    )
  ),
  model_assignment_set_hash TEXT NOT NULL CHECK (
    length(model_assignment_set_hash) = 64
    AND model_assignment_set_hash NOT GLOB '*[^0-9a-f]*'
  ),
  evidence_policy_hash TEXT NOT NULL CHECK (
    length(evidence_policy_hash) = 64
    AND evidence_policy_hash NOT GLOB '*[^0-9a-f]*'
  ),
  brain_context_pack_id TEXT NOT NULL
    REFERENCES memory_context_packs(id) ON DELETE RESTRICT,
  brain_context_pack_hash TEXT NOT NULL CHECK (
    length(brain_context_pack_hash) = 64
    AND brain_context_pack_hash NOT GLOB '*[^0-9a-f]*'
  ),
  selected_action_class_ids_json TEXT NOT NULL CHECK (
    json_valid(selected_action_class_ids_json)
    AND json_type(selected_action_class_ids_json) = 'array'
  ),
  selected_action_class_count INTEGER NOT NULL
    CHECK (selected_action_class_count > 0),
  activated_action_class_count INTEGER NOT NULL CHECK (
    activated_action_class_count > 0
    AND activated_action_class_count = selected_action_class_count
  ),
  route_set_hash TEXT NOT NULL CHECK (
    length(route_set_hash) = 64 AND route_set_hash NOT GLOB '*[^0-9a-f]*'
  ),
  issued_by TEXT NOT NULL CHECK (length(trim(issued_by)) > 0),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL CHECK (expires_at > issued_at),
  receipt_hash TEXT NOT NULL UNIQUE CHECK (
    length(receipt_hash) = 64 AND receipt_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (
    (
      planning_route = 'local_deterministic'
      AND planning_model_assignment_id IS NULL
      AND planning_primary_configuration_id IS NULL
      AND planning_fallback_configuration_id IS NULL
      AND planning_primary_configuration_hash IS NULL
      AND planning_fallback_configuration_hash IS NULL
    )
    OR (
      planning_route = 'provider_advisory'
      AND planning_model_assignment_id IS NOT NULL
      AND planning_primary_configuration_id IS NOT NULL
      AND planning_primary_configuration_hash IS NOT NULL
    )
  ),
  UNIQUE (run_id, generation)
) STRICT;

CREATE INDEX idx_autonomous_activation_receipts_run_generation
  ON autonomous_activation_receipts(run_id, generation DESC);

CREATE INDEX idx_autonomous_activation_receipts_contract
  ON autonomous_activation_receipts(contract_id, issued_at DESC);

CREATE TABLE autonomous_activation_receipt_items (
  receipt_id TEXT NOT NULL
    REFERENCES autonomous_activation_receipts(id) ON DELETE RESTRICT,
  action_class_id TEXT NOT NULL CHECK (length(trim(action_class_id)) > 0),
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
  execution_model_assignment_id TEXT NOT NULL
    REFERENCES agent_model_assignments(id) ON DELETE RESTRICT,
  execution_primary_configuration_id TEXT NOT NULL
    REFERENCES model_configurations(id) ON DELETE RESTRICT,
  execution_fallback_configuration_id TEXT
    REFERENCES model_configurations(id) ON DELETE RESTRICT,
  tool_id TEXT NOT NULL CHECK (length(trim(tool_id)) > 0),
  tool_binding_kind TEXT NOT NULL CHECK (
    tool_binding_kind IN ('local', 'mcp')
  ),
  mcp_server_id TEXT REFERENCES mcp_servers(id) ON DELETE RESTRICT,
  tool_activation_receipt_id TEXT NOT NULL CHECK (
    length(trim(tool_activation_receipt_id)) > 0
  ),
  tool_activation_receipt_hash TEXT NOT NULL CHECK (
    length(tool_activation_receipt_hash) = 64
    AND tool_activation_receipt_hash NOT GLOB '*[^0-9a-f]*'
  ),
  tool_manifest_hash TEXT NOT NULL CHECK (
    length(tool_manifest_hash) = 64
    AND tool_manifest_hash NOT GLOB '*[^0-9a-f]*'
  ),
  evidence_type_ids_json TEXT NOT NULL CHECK (
    json_valid(evidence_type_ids_json)
    AND json_type(evidence_type_ids_json) = 'array'
    AND json_array_length(evidence_type_ids_json) > 0
  ),
  evidence_producer_ids_json TEXT NOT NULL CHECK (
    json_valid(evidence_producer_ids_json)
    AND json_type(evidence_producer_ids_json) = 'array'
    AND json_array_length(evidence_producer_ids_json) > 0
  ),
  route_expires_at TEXT NOT NULL,
  route_hash TEXT NOT NULL CHECK (
    length(route_hash) = 64 AND route_hash NOT GLOB '*[^0-9a-f]*'
  ),
  created_at TEXT NOT NULL,
  PRIMARY KEY (receipt_id, action_class_id),
  UNIQUE (receipt_id, route_hash),
  CHECK (
    (tool_binding_kind = 'local' AND mcp_server_id IS NULL)
    OR (tool_binding_kind = 'mcp' AND mcp_server_id IS NOT NULL)
  )
) STRICT;

CREATE INDEX idx_autonomous_activation_items_execution_assignment
  ON autonomous_activation_receipt_items(execution_model_assignment_id);

CREATE INDEX idx_autonomous_activation_receipts_planning_assignment
  ON autonomous_activation_receipts(planning_model_assignment_id)
  WHERE planning_model_assignment_id IS NOT NULL;

CREATE TABLE autonomous_activation_bindings (
  id TEXT PRIMARY KEY,
  receipt_id TEXT NOT NULL
    REFERENCES autonomous_activation_receipts(id) ON DELETE RESTRICT,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  binding_type TEXT NOT NULL CHECK (binding_type IN (
    'launch', 'planning', 'plan_version', 'dispatch', 'resume',
    'restart_recovery'
  )),
  subject_id TEXT NOT NULL CHECK (length(trim(subject_id)) > 0),
  subject_digest TEXT NOT NULL CHECK (
    length(subject_digest) = 64 AND subject_digest NOT GLOB '*[^0-9a-f]*'
  ),
  runtime_generation_hash TEXT NOT NULL CHECK (
    length(runtime_generation_hash) = 64
    AND runtime_generation_hash NOT GLOB '*[^0-9a-f]*'
  ),
  plan_id TEXT REFERENCES plans(id) ON DELETE RESTRICT,
  step_id TEXT REFERENCES plan_steps(id) ON DELETE RESTRICT,
  action_id TEXT REFERENCES actions(id) ON DELETE RESTRICT,
  context_pack_id TEXT REFERENCES memory_context_packs(id) ON DELETE RESTRICT,
  provider_turn_id TEXT REFERENCES provider_turns(id) ON DELETE RESTRICT,
  previous_binding_hash TEXT CHECK (
    previous_binding_hash IS NULL
    OR (
      length(previous_binding_hash) = 64
      AND previous_binding_hash NOT GLOB '*[^0-9a-f]*'
    )
  ),
  bound_by TEXT NOT NULL CHECK (length(trim(bound_by)) > 0),
  bound_at TEXT NOT NULL,
  binding_hash TEXT NOT NULL UNIQUE CHECK (
    length(binding_hash) = 64 AND binding_hash NOT GLOB '*[^0-9a-f]*'
  ),
  UNIQUE (receipt_id, sequence),
  CHECK (
    (sequence = 1 AND previous_binding_hash IS NULL)
    OR (sequence > 1 AND previous_binding_hash IS NOT NULL)
  )
) STRICT;

CREATE INDEX idx_autonomous_activation_bindings_receipt_sequence
  ON autonomous_activation_bindings(receipt_id, sequence);

CREATE INDEX idx_autonomous_activation_bindings_action
  ON autonomous_activation_bindings(action_id)
  WHERE action_id IS NOT NULL;

CREATE TRIGGER trg_autonomous_activation_receipt_lineage_insert
BEFORE INSERT ON autonomous_activation_receipts
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM missions AS mission
    JOIN runs AS run
      ON run.id = NEW.run_id
      AND run.mission_id = mission.id
      AND run.journey = 'autonomous'
      AND run.contract_id = NEW.contract_id
      AND run.contract_version_bound = NEW.contract_version
      AND run.contract_hash_bound = NEW.contract_hash
    JOIN mission_contracts AS contract
      ON contract.id = NEW.contract_id
      AND contract.mission_id = mission.id
      AND contract.version = NEW.contract_version
      AND contract.contract_hash = NEW.contract_hash
      AND contract.state = 'confirmed'
    JOIN memory_context_packs AS context_pack
      ON context_pack.id = NEW.brain_context_pack_id
      AND context_pack.mission_id = mission.id
      AND context_pack.run_id = run.id
      AND context_pack.journey = 'autonomous'
    WHERE mission.id = NEW.mission_id
      AND mission.journey = 'autonomous'
  ) THEN RAISE(
    ABORT,
    'Autonomous activation receipt lineage does not match the confirmed run contract and Context Pack'
  ) END;

  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM mission_contracts AS contract
    WHERE contract.id = NEW.contract_id
      AND (
        (
          NEW.planning_route = 'local_deterministic'
          AND json_extract(
            contract.action_policy_json,
            '$.planningSelection.route'
          ) = 'local_deterministic'
          AND json_extract(
            NEW.planning_selection_json,
            '$.route'
          ) = 'local_deterministic'
          AND NEW.planning_planner_id = json_extract(
            contract.action_policy_json,
            '$.planningSelection.plannerId'
          )
          AND json_extract(
            NEW.planning_selection_json,
            '$.plannerId'
          ) = NEW.planning_planner_id
          AND json_extract(
            NEW.planning_selection_json,
            '$.enforcementMode'
          ) = json_extract(
            contract.action_policy_json,
            '$.planningSelection.enforcementMode'
          )
          AND json_extract(
            NEW.planning_selection_json,
            '$.disclosureClass'
          ) = json_extract(
            contract.action_policy_json,
            '$.planningSelection.disclosureClass'
          )
          AND json_extract(
            NEW.planning_selection_json,
            '$.executionAuthority'
          ) = json_extract(
            contract.action_policy_json,
            '$.planningSelection.executionAuthority'
          )
        )
        OR (
          NEW.planning_route = 'provider_advisory'
          AND json_extract(
            contract.action_policy_json,
            '$.planningSelection.route'
          ) = 'provider_advisory'
          AND json_extract(
            NEW.planning_selection_json,
            '$.route'
          ) = 'provider_advisory'
          AND NEW.planning_planner_id = json_extract(
            contract.action_policy_json,
            '$.planningSelection.agentId'
          )
          AND json_extract(
            NEW.planning_selection_json,
            '$.agentId'
          ) = NEW.planning_planner_id
          AND NEW.planning_primary_configuration_id = json_extract(
            contract.action_policy_json,
            '$.planningSelection.primaryConfigurationId'
          )
          AND json_extract(
            NEW.planning_selection_json,
            '$.primaryConfigurationId'
          ) = NEW.planning_primary_configuration_id
          AND NEW.planning_fallback_configuration_id IS json_extract(
            contract.action_policy_json,
            '$.planningSelection.fallbackConfigurationId'
          )
          AND json_extract(
            NEW.planning_selection_json,
            '$.fallbackConfigurationId'
          ) IS NEW.planning_fallback_configuration_id
          AND json_extract(
            NEW.planning_selection_json,
            '$.enforcementMode'
          ) = json_extract(
            contract.action_policy_json,
            '$.planningSelection.enforcementMode'
          )
          AND json_extract(
            NEW.planning_selection_json,
            '$.disclosureClass'
          ) = json_extract(
            contract.action_policy_json,
            '$.planningSelection.disclosureClass'
          )
          AND json_extract(
            NEW.planning_selection_json,
            '$.executionAuthority'
          ) = json_extract(
            contract.action_policy_json,
            '$.planningSelection.executionAuthority'
          )
        )
      )
  ) THEN RAISE(
    ABORT,
    'Autonomous activation planning selection does not exactly match the signed contract'
  ) END;

  SELECT CASE WHEN NEW.planning_route = 'provider_advisory'
    AND NOT EXISTS (
      SELECT 1
      FROM agent_model_assignments AS planning_assignment
      JOIN model_configurations AS planning_configuration
        ON planning_configuration.id =
          planning_assignment.primary_configuration_id
        AND (
          CASE planning_configuration.enforcement_mode
            WHEN 'advisory_only' THEN 'advisor_only'
            ELSE 'not_advisor_only'
          END
        ) = 'advisor_only'
        AND (
          CASE planning_configuration.auth_state
            WHEN 'healthy' THEN 'authenticated'
            ELSE 'not_authenticated'
          END
        ) = 'authenticated'
        AND planning_configuration.health_state = 'healthy'
      WHERE planning_assignment.id = NEW.planning_model_assignment_id
        AND planning_assignment.mission_id = NEW.mission_id
        AND planning_assignment.run_id = NEW.run_id
        AND planning_assignment.step_id IS NULL
        AND planning_assignment.agent_id = NEW.planning_planner_id
        AND planning_assignment.assignment_purpose = 'planning'
        AND planning_assignment.pinned = 1
        AND planning_assignment.primary_configuration_id =
          NEW.planning_primary_configuration_id
        AND planning_assignment.fallback_configuration_id IS
          NEW.planning_fallback_configuration_id
        AND (
          NEW.planning_fallback_configuration_id IS NULL
          OR EXISTS (
            SELECT 1
            FROM model_configurations AS fallback_configuration
            WHERE fallback_configuration.id =
              NEW.planning_fallback_configuration_id
              AND (
                CASE fallback_configuration.enforcement_mode
                  WHEN 'advisory_only' THEN 'advisor_only'
                  ELSE 'not_advisor_only'
                END
              ) = 'advisor_only'
              AND (
                CASE fallback_configuration.auth_state
                  WHEN 'healthy' THEN 'authenticated'
                  ELSE 'not_authenticated'
                END
              ) = 'authenticated'
              AND fallback_configuration.health_state = 'healthy'
          )
        )
    )
  THEN RAISE(
    ABORT,
    'Autonomous activation provider planner is not one exact healthy purpose=planning run pin'
  ) END;

  SELECT CASE WHEN json_array_length(
    NEW.selected_action_class_ids_json
  ) != NEW.selected_action_class_count
  THEN RAISE(
    ABORT,
    'Autonomous activation selected action-class count is inconsistent'
  ) END;

  SELECT CASE WHEN EXISTS (
    SELECT 1
    FROM json_each(NEW.selected_action_class_ids_json)
    WHERE type != 'text' OR length(trim(value)) = 0
  ) THEN RAISE(
    ABORT,
    'Autonomous activation action-class IDs must be non-empty strings'
  ) END;

  SELECT CASE WHEN (
    SELECT count(*) FROM json_each(NEW.selected_action_class_ids_json)
  ) != (
    SELECT count(DISTINCT value)
    FROM json_each(NEW.selected_action_class_ids_json)
  ) THEN RAISE(
    ABORT,
    'Autonomous activation action-class IDs must be unique'
  ) END;

  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.selected_action_class_ids_json) AS selected
    WHERE NOT EXISTS (
      SELECT 1
      FROM mission_contracts AS contract,
        json_each(contract.action_policy_json, '$.allowedActionClasses') AS allowed
      WHERE contract.id = NEW.contract_id
        AND allowed.type = 'text'
        AND allowed.value = selected.value
    )
  ) OR EXISTS (
    SELECT 1
    FROM mission_contracts AS contract,
      json_each(contract.action_policy_json, '$.allowedActionClasses') AS allowed
    WHERE contract.id = NEW.contract_id
      AND allowed.type = 'text'
      AND NOT EXISTS (
        SELECT 1 FROM json_each(NEW.selected_action_class_ids_json) AS selected
        WHERE selected.value = allowed.value
      )
  ) THEN RAISE(
    ABORT,
    'Autonomous activation action classes do not exactly match the signed contract'
  ) END;

  SELECT CASE WHEN NEW.generation != (
    SELECT COALESCE(MAX(existing.generation), 0) + 1
    FROM autonomous_activation_receipts AS existing
    WHERE existing.run_id = NEW.run_id
  ) THEN RAISE(
    ABORT,
    'Autonomous activation receipt generation is not the next run generation'
  ) END;
END;

CREATE TRIGGER trg_autonomous_activation_item_lineage_insert
BEFORE INSERT ON autonomous_activation_receipt_items
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM autonomous_activation_receipts AS receipt,
      json_each(receipt.selected_action_class_ids_json) AS selected
    WHERE receipt.id = NEW.receipt_id
      AND selected.type = 'text'
      AND selected.value = NEW.action_class_id
      AND NEW.route_expires_at >= receipt.expires_at
  ) THEN RAISE(
    ABORT,
    'Autonomous activation item is outside the receipt action-class or expiry boundary'
  ) END;

  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM autonomous_activation_receipts AS receipt
    JOIN agent_model_assignments AS execution_assignment
      ON execution_assignment.id = NEW.execution_model_assignment_id
      AND execution_assignment.mission_id = receipt.mission_id
      AND execution_assignment.run_id = receipt.run_id
      AND execution_assignment.step_id IS NULL
      AND execution_assignment.agent_id = NEW.agent_id
      AND execution_assignment.assignment_purpose = 'execution'
      AND execution_assignment.pinned = 1
      AND execution_assignment.primary_configuration_id =
        NEW.execution_primary_configuration_id
      AND execution_assignment.fallback_configuration_id IS
        NEW.execution_fallback_configuration_id
    JOIN model_configurations AS execution_configuration
      ON execution_configuration.id =
        NEW.execution_primary_configuration_id
      AND (
        CASE execution_configuration.enforcement_mode
          WHEN 'enforced' THEN 'enforced_executor'
          ELSE 'not_enforced_executor'
        END
      ) = 'enforced_executor'
      AND (
        CASE execution_configuration.auth_state
          WHEN 'healthy' THEN 'authenticated'
          ELSE 'not_authenticated'
        END
      ) = 'authenticated'
      AND execution_configuration.health_state = 'healthy'
    WHERE receipt.id = NEW.receipt_id
      AND (
        NEW.execution_fallback_configuration_id IS NULL
        OR EXISTS (
          SELECT 1
          FROM model_configurations AS fallback_configuration
          WHERE fallback_configuration.id =
            NEW.execution_fallback_configuration_id
            AND (
              CASE fallback_configuration.enforcement_mode
                WHEN 'enforced' THEN 'enforced_executor'
                ELSE 'not_enforced_executor'
              END
            ) = 'enforced_executor'
            AND (
              CASE fallback_configuration.auth_state
                WHEN 'healthy' THEN 'authenticated'
                ELSE 'not_authenticated'
              END
            ) = 'authenticated'
            AND fallback_configuration.health_state = 'healthy'
        )
      )
  ) THEN RAISE(
    ABORT,
    'Autonomous activation execution assignment is not an exact enforced run pin'
  ) END;

  SELECT CASE WHEN (
    SELECT count(*)
    FROM autonomous_activation_receipt_items
    WHERE receipt_id = NEW.receipt_id
  ) >= (
    SELECT activated_action_class_count
    FROM autonomous_activation_receipts
    WHERE id = NEW.receipt_id
  ) THEN RAISE(
    ABORT,
    'Autonomous activation receipt already has its complete route set'
  ) END;

  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.evidence_type_ids_json)
    WHERE type != 'text' OR length(trim(value)) = 0
  ) OR (
    SELECT count(*) FROM json_each(NEW.evidence_type_ids_json)
  ) != (
    SELECT count(DISTINCT value)
    FROM json_each(NEW.evidence_type_ids_json)
  ) THEN RAISE(
    ABORT,
    'Autonomous activation evidence type IDs must be unique non-empty strings'
  ) END;

  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.evidence_producer_ids_json)
    WHERE type != 'text' OR length(trim(value)) = 0
  ) OR (
    SELECT count(*) FROM json_each(NEW.evidence_producer_ids_json)
  ) != (
    SELECT count(DISTINCT value)
    FROM json_each(NEW.evidence_producer_ids_json)
  ) THEN RAISE(
    ABORT,
    'Autonomous activation evidence producer IDs must be unique non-empty strings'
  ) END;
END;

CREATE TRIGGER trg_autonomous_activation_binding_lineage_insert
BEFORE INSERT ON autonomous_activation_bindings
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1
    FROM autonomous_activation_receipts AS receipt
    WHERE receipt.id = NEW.receipt_id
      AND receipt.runtime_generation_hash = NEW.runtime_generation_hash
      AND NEW.bound_at <= receipt.expires_at
      AND (
        SELECT count(*)
        FROM autonomous_activation_receipt_items AS item
        WHERE item.receipt_id = receipt.id
      ) = receipt.activated_action_class_count
  ) THEN RAISE(
    ABORT,
    'Autonomous activation binding requires a complete unexpired receipt generation'
  ) END;

  SELECT CASE WHEN (
    NEW.sequence = 1 AND NOT EXISTS (
      SELECT 1
      FROM autonomous_activation_receipts AS receipt
      WHERE receipt.id = NEW.receipt_id
        AND NEW.binding_type = 'launch'
        AND NEW.subject_id = receipt.run_id
        AND NEW.subject_digest = receipt.receipt_hash
        AND NEW.context_pack_id = receipt.brain_context_pack_id
        AND NEW.plan_id IS NULL
        AND NEW.step_id IS NULL
        AND NEW.action_id IS NULL
        AND NEW.provider_turn_id IS NULL
    )
  ) OR (
    NEW.sequence > 1 AND NEW.binding_type = 'launch'
  ) THEN RAISE(
    ABORT,
    'Autonomous activation launch seal is missing or not the first exact binding'
  ) END;

  SELECT CASE WHEN NEW.sequence > 1 AND NOT EXISTS (
    SELECT 1
    FROM autonomous_activation_bindings AS previous
    WHERE previous.receipt_id = NEW.receipt_id
      AND previous.sequence = NEW.sequence - 1
      AND previous.binding_hash = NEW.previous_binding_hash
  ) THEN RAISE(
    ABORT,
    'Autonomous activation binding chain predecessor is invalid'
  ) END;

  SELECT CASE WHEN NEW.plan_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM plans AS plan
    JOIN autonomous_activation_receipts AS receipt
      ON receipt.id = NEW.receipt_id AND receipt.run_id = plan.run_id
    WHERE plan.id = NEW.plan_id
  ) THEN RAISE(
    ABORT,
    'Autonomous activation plan binding is outside the receipt run'
  ) END;

  SELECT CASE WHEN NEW.step_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM plan_steps AS step
    JOIN autonomous_activation_receipts AS receipt
      ON receipt.id = NEW.receipt_id AND receipt.run_id = step.run_id
    WHERE step.id = NEW.step_id
  ) THEN RAISE(
    ABORT,
    'Autonomous activation step binding is outside the receipt run'
  ) END;

  SELECT CASE WHEN NEW.action_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM actions AS action
    JOIN autonomous_activation_receipts AS receipt
      ON receipt.id = NEW.receipt_id
      AND receipt.run_id = action.run_id
      AND receipt.mission_id = action.mission_id
    WHERE action.id = NEW.action_id
  ) THEN RAISE(
    ABORT,
    'Autonomous activation action binding is outside the receipt boundary'
  ) END;

  SELECT CASE WHEN NEW.context_pack_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM memory_context_packs AS context_pack
    JOIN autonomous_activation_receipts AS receipt
      ON receipt.id = NEW.receipt_id
      AND receipt.run_id = context_pack.run_id
      AND receipt.mission_id = context_pack.mission_id
      AND context_pack.journey = 'autonomous'
    WHERE context_pack.id = NEW.context_pack_id
  ) THEN RAISE(
    ABORT,
    'Autonomous activation Context Pack binding is outside the receipt boundary'
  ) END;

  SELECT CASE WHEN NEW.provider_turn_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM provider_turns AS provider_turn
    JOIN autonomous_activation_receipts AS receipt
      ON receipt.id = NEW.receipt_id
      AND receipt.run_id = provider_turn.run_id
    WHERE provider_turn.id = NEW.provider_turn_id
  ) THEN RAISE(
    ABORT,
    'Autonomous activation provider-turn binding is outside the receipt run'
  ) END;
END;

CREATE TRIGGER trg_autonomous_activation_receipt_immutable_update
BEFORE UPDATE ON autonomous_activation_receipts
BEGIN
  SELECT RAISE(ABORT, 'Autonomous activation receipts are immutable');
END;

CREATE TRIGGER trg_autonomous_activation_receipt_immutable_delete
BEFORE DELETE ON autonomous_activation_receipts
BEGIN
  SELECT RAISE(ABORT, 'Autonomous activation receipts are immutable');
END;

CREATE TRIGGER trg_autonomous_activation_item_immutable_update
BEFORE UPDATE ON autonomous_activation_receipt_items
BEGIN
  SELECT RAISE(ABORT, 'Autonomous activation route items are immutable');
END;

CREATE TRIGGER trg_autonomous_activation_item_immutable_delete
BEFORE DELETE ON autonomous_activation_receipt_items
BEGIN
  SELECT RAISE(ABORT, 'Autonomous activation route items are immutable');
END;

CREATE TRIGGER trg_autonomous_activation_binding_immutable_update
BEFORE UPDATE ON autonomous_activation_bindings
BEGIN
  SELECT RAISE(ABORT, 'Autonomous activation bindings are append-only');
END;

CREATE TRIGGER trg_autonomous_activation_binding_immutable_delete
BEFORE DELETE ON autonomous_activation_bindings
BEGIN
  SELECT RAISE(ABORT, 'Autonomous activation bindings are append-only');
END;
`,
};
