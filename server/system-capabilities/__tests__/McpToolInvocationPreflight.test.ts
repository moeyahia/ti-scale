import { describe, expect, test } from "bun:test";
import { FailureDiagnosisService } from "../../intelligence-v24/FailureDiagnosisService";
import {
  deterministicOptions,
  testDatabase,
} from "../../intelligence-v24/__tests__/fixtures";
import { digestCanonicalJson } from "../../mcp/canonicalJson";
import type { McpToolCapabilityAttestation } from "../../mcp/types";
import {
  mcpToolFailureDiagnosisInput,
  preflightMcpToolInvocation,
} from "../McpToolInvocationPreflight";

const BOARD_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: false,
  required: ["missionId", "title", "details"],
  properties: {
    missionId: { type: "string", minLength: 1, maxLength: 128 },
    title: { type: "string", minLength: 4, maxLength: 200 },
    details: { type: "string", minLength: 10, maxLength: 4_000 },
    priority: { type: "string", enum: ["low", "normal", "high"] },
  },
} as const);

function attestedTool(
  schema: Readonly<Record<string, unknown>> = BOARD_SCHEMA,
  overrides: Partial<McpToolCapabilityAttestation> = {},
): McpToolCapabilityAttestation {
  const digest = digestCanonicalJson(schema, { maxBytes: 64 * 1_024, maxDepth: 32 });
  return {
    name: "board_create_task",
    description: "Create one represented mission-board task.",
    inputSchema: schema,
    inputSchemaSha256: digest.sha256,
    inputSchemaBytes: digest.bytes,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    ...overrides,
  };
}

function validArguments() {
  return {
    missionId: "mission-one",
    title: "ReaperTwo current-IP TCP baseline",
    details: "Verify reachability, complete TCP discovery, then fingerprint each discovered service.",
    priority: "high",
  };
}

describe("exact MCP tool invocation preflight and failure diagnosis", () => {
  test("accepts a valid board_create_task payload while retaining hashes instead of argument values", () => {
    const result = preflightMcpToolInvocation({
      serverId: "mission-board",
      requestedToolName: "board_create_task",
      attestedTool: attestedTool(),
      arguments: validArguments(),
    });

    expect(result).toMatchObject({
      schemaVersion: "ti-scale.mcp-tool-invocation-preflight.v1",
      status: "ready",
      code: "ready",
      serverId: "mission-board",
      toolName: "board_create_task",
      targetContact: false,
      executionAuthorization: "none",
      issues: [],
    });
    expect(result.inputSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.inputSchemaSha256).toMatch(/^[a-f0-9]{64}$/);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain("ReaperTwo");
    expect(serialized).not.toContain("mission-one");
  });

  test("rejects missing, short, enum-invalid, and undeclared board fields before dispatch", () => {
    const result = preflightMcpToolInvocation({
      serverId: "mission-board",
      requestedToolName: "board_create_task",
      attestedTool: attestedTool(),
      arguments: {
        missionId: "mission-one",
        title: "TCP",
        details: "short",
        priority: "urgent",
        staleEngagementPath: "/root/htb/boxes/ReaperTwo",
      },
    });

    expect(result).toMatchObject({
      status: "rejected",
      code: "input_invalid",
      targetContact: false,
      executionAuthorization: "none",
    });
    expect(result.issues).toEqual([
      { path: "/title", code: "min_length", message: "Enter at least 4 characters." },
      { path: "/details", code: "min_length", message: "Enter at least 10 characters." },
      { path: "/priority", code: "enum", message: "The value is not one of the tool's accepted options." },
      { path: "/staleEngagementPath", code: "additional_property", message: "Remove the unsupported “staleEngagementPath” field." },
    ]);
    expect(JSON.stringify(result)).not.toContain("/root/htb");
    expect(result.remediation).toContain("do not repeat the unchanged request");
  });

  test("reports the exact required board field instead of allowing an opaque HTTP 400", () => {
    const result = preflightMcpToolInvocation({
      serverId: "mission-board",
      requestedToolName: "board_create_task",
      attestedTool: attestedTool(),
      arguments: {
        missionId: "mission-one",
        details: "Create an attributable current-IP reconnaissance task without stale evidence.",
      },
    });

    expect(result).toMatchObject({ status: "rejected", code: "input_invalid" });
    expect(result.issues).toContainEqual({
      path: "/title",
      code: "required",
      message: "Provide the required “title” field.",
    });
  });

  test("fails closed on schema drift or a constraint the local validator cannot enforce", () => {
    const schemaDrift = preflightMcpToolInvocation({
      serverId: "mission-board",
      requestedToolName: "board_create_task",
      attestedTool: attestedTool(BOARD_SCHEMA, { inputSchemaSha256: "f".repeat(64) }),
      arguments: validArguments(),
    });
    expect(schemaDrift).toMatchObject({ status: "rejected", code: "schema_binding_mismatch" });

    const patternSchema = {
      type: "object",
      properties: { title: { type: "string", pattern: "^[a-z]+$" } },
    };
    const unsupported = preflightMcpToolInvocation({
      serverId: "mission-board",
      requestedToolName: "board_create_task",
      attestedTool: attestedTool(patternSchema),
      arguments: { title: "task" },
    });
    expect(unsupported).toMatchObject({ status: "rejected", code: "schema_unsupported" });
    expect(unsupported.issues[0]?.message).toContain("pattern");
  });

  test("turns the five observed board HTTP 400 responses into one persisted non-retryable diagnosis", () => {
    const preflight = preflightMcpToolInvocation({
      serverId: "mission-board",
      requestedToolName: "board_create_task",
      attestedTool: attestedTool(),
      arguments: validArguments(),
    });
    const database = testDatabase();
    try {
      const service = new FailureDiagnosisService(database, deterministicOptions());
      const diagnosis = service.create(mcpToolFailureDiagnosisInput(preflight, {
        httpStatus: 400,
        transportCode: "HTTPError: HTTP Error 400: Bad Request",
        attemptCount: 5,
      }, {
        missionId: "mission-one",
        runId: "run-one",
        targetSummary: "Local mission-board task creation for the current ReaperTwo plan.",
        actor: { id: "mcp-runtime", type: "system" },
      }));

      expect(diagnosis).toMatchObject({
        category: "invalid_input",
        code: "mcp_http_400_contract_rejected",
        originatingComponent: "mcp-tool-runtime",
        failedComponentRef: "mission-board/board_create_task",
        retryable: false,
        state: "active",
      });
      expect(diagnosis.humanReason).toBe(
        "mission-board rejected board_create_task with HTTP 400 after the payload passed its locally attested input schema. The server has an additional constraint or its binding changed; repeating identical parameters is disabled.",
      );
      expect(diagnosis.operatorActions.map(({ kind }) => kind)).toEqual([
        "amend_plan",
        "configure_dependency",
        "use_compatible_fallback",
      ]);
      expect(diagnosis.retryHistory).toHaveLength(5);
      expect(diagnosis.automaticRecovery).toMatchObject({
        attempted: false,
        repeatedUnchangedDispatchSuppressed: true,
        attemptCount: 5,
      });
      expect(JSON.stringify(diagnosis)).not.toContain("HTTPError: HTTP Error 400");
      expect(database.prepare("SELECT COUNT(*) AS count FROM failure_diagnoses").get()).toEqual({ count: 1 });
      expect(database.prepare("SELECT COUNT(*) AS count FROM audit_records").get()).toEqual({ count: 1 });
    } finally {
      database.close();
    }
  });

  test("persists field-level correction guidance when the board request fails local validation", () => {
    const preflight = preflightMcpToolInvocation({
      serverId: "mission-board",
      requestedToolName: "board_create_task",
      attestedTool: attestedTool(),
      arguments: { missionId: "mission-one", details: "Long enough task details." },
    });
    const database = testDatabase();
    try {
      const diagnosis = new FailureDiagnosisService(database, deterministicOptions()).create(
        mcpToolFailureDiagnosisInput(preflight, { attemptCount: 1 }, {
          missionId: "mission-one",
          runId: "run-one",
          actor: { id: "mcp-runtime", type: "system" },
        }),
      );
      expect(diagnosis).toMatchObject({
        category: "invalid_input",
        code: "mcp_preflight_input_invalid",
        retryable: false,
        targetSummary: "The tool was not dispatched and no target interaction began.",
      });
      expect(diagnosis.humanReason).toContain('/title: Provide the required “title” field.');
      expect(diagnosis.progressBeforeFailure).toMatchObject({
        inputSchemaValidated: false,
        targetContact: false,
        acceptedToolResult: false,
      });
    } finally {
      database.close();
    }
  });

  test("keeps a real rate limit distinct from deterministic HTTP 400 input failure", () => {
    const preflight = preflightMcpToolInvocation({
      serverId: "mission-board",
      requestedToolName: "board_create_task",
      attestedTool: attestedTool(),
      arguments: validArguments(),
    });
    const input = mcpToolFailureDiagnosisInput(preflight, {
      httpStatus: 429,
      retryAfterMs: 30_000,
    }, {
      missionId: "mission-one",
      runId: "run-one",
      actor: { id: "mcp-runtime", type: "system" },
    });
    expect(input).toMatchObject({
      category: "rate_limit",
      code: "mcp_http_429_rate_limit",
      retryable: true,
    });
    expect(input.humanReason).toContain("allowed request rate");
    expect(input.remediation).toContain("30000 ms");
    expect(input.operatorActions.map(({ kind }) => kind)).toContain("retry_bounded");
  });
});
