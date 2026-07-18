/**
 * Canonical database predicates for the operational-log/evidence boundary.
 *
 * Historical runtime versions persisted successful MCP output as a verified
 * `tool_result` even though success only described the process exit, not the
 * truth of the output. New runtime output is retained as `command_output` and
 * is never evidence by itself. A historical MCP tool result can qualify only
 * after an explicit immutable `verified` custody event has been appended.
 */
function evidenceAlias(alias: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(alias)) {
    throw new Error(`Invalid evidence SQL alias: ${alias}`);
  }
  return alias;
}

export function evidenceRecordSql(alias = "e"): string {
  const evidence = evidenceAlias(alias);
  return `(
    lower(trim(${evidence}.evidence_type)) <> 'command_output'
    AND NOT (
      lower(trim(${evidence}.source)) LIKE 'mcp:%'
      AND lower(trim(${evidence}.evidence_type)) = 'tool_result'
      AND NOT EXISTS (
        SELECT 1 FROM evidence_chain_events evidence_verification
        WHERE evidence_verification.evidence_id = ${evidence}.id
          AND evidence_verification.event_type = 'verified'
      )
    )
  )`;
}

export function verifiedEvidenceSql(alias = "e"): string {
  const evidence = evidenceAlias(alias);
  return `
    ${evidence}.verification_state = 'verified'
    AND ${evidenceRecordSql(evidence)}
  `;
}
