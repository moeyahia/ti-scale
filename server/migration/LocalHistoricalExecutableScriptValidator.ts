import { createHash, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { digestCanonicalJson } from "../mcp";
import { REVIEWED_PYTHON_INTERPRETER_BINDING_ID } from "../exploit-sandbox/types";
import { assertNoEmbeddedSecrets } from "../script-artifacts";
import {
  HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_RECEIPT_SCHEMA,
  HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_SCHEMA,
  HistoricalExecutableScriptPromotionError,
  type HistoricalExecutableScriptValidationPort,
  type HistoricalExecutableScriptValidationReceipt,
  type HistoricalExecutableScriptValidationRequest,
} from "./HistoricalExecutableScriptPromotionService";

function sourceHash(source: string): string {
  return createHash("sha256").update(source, "utf8").digest("hex");
}

/**
 * Non-executing local validator for the one interpreter binding accepted by
 * the current exact-target runtime. Python's AST parser receives the source
 * over stdin; the historical program is never imported or executed.
 */
export class LocalHistoricalExecutableScriptValidator
implements HistoricalExecutableScriptValidationPort {
  constructor(private readonly options: Readonly<{
    pythonPath?: string;
    clock?: () => Date;
    timeoutMs?: number;
  }> = {}) {}

  async validate(
    request: HistoricalExecutableScriptValidationRequest,
  ): Promise<HistoricalExecutableScriptValidationReceipt> {
    if (request.schemaVersion !== HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_SCHEMA
      || request.language !== "python"
      || request.publicProvider
      || request.targetContact
      || request.sourceExecution
      || sourceHash(request.source) !== request.sourceHash) {
      throw new HistoricalExecutableScriptPromotionError(
        "historical_script_validation_request_invalid",
        "Local validation requires exact unchanged Python source under the no-provider, no-target, non-executing boundary.",
      );
    }
    assertNoEmbeddedSecrets(request.source);
    const workspace = mkdtempSync(join(tmpdir(), "ti-scale-script-validate-"));
    try {
      const result = spawnSync(
        this.options.pythonPath ?? "/usr/bin/python3",
        [
          "-I",
          "-S",
          "-c",
          "import ast,sys; ast.parse(sys.stdin.read(), filename='<reviewed-historical-source>', mode='exec')",
        ],
        {
          cwd: workspace,
          env: {
            PATH: "/usr/bin:/bin",
            PYTHONDONTWRITEBYTECODE: "1",
            PYTHONNOUSERSITE: "1",
          },
          input: request.source,
          encoding: "utf8",
          timeout: this.options.timeoutMs ?? 5_000,
          maxBuffer: 64 * 1_024,
          shell: false,
          windowsHide: true,
        },
      );
      if (result.error || result.status !== 0 || result.signal) {
        throw new HistoricalExecutableScriptPromotionError(
          "historical_script_local_syntax_validation_failed",
          "The reviewed historical source did not pass isolated non-executing Python syntax validation.",
        );
      }
      const validatedAt = (this.options.clock?.() ?? new Date()).toISOString();
      const material = {
        schemaVersion: HISTORICAL_EXECUTABLE_SCRIPT_VALIDATION_RECEIPT_SCHEMA,
        receiptId: `historical_script_validation_${randomUUID()}`,
        bundleId: request.bundleId,
        migrationId: request.migrationId,
        sourceCandidateId: request.sourceCandidateId,
        sourceHash: request.sourceHash,
        language: request.language,
        validatorBindingId:
          `${REVIEWED_PYTHON_INTERPRETER_BINDING_ID}:nonexecuting-ast-v1`,
        tests: [{
          name: "Immutable source continuity",
          status: "passed" as const,
          summary: "The locally read source bytes match the operator-reviewed SHA-256 custody.",
        }, {
          name: "Embedded-secret rejection",
          status: "passed" as const,
          summary: "The local deterministic secret scan found no reusable secret-bearing material.",
        }, {
          name: "Non-executing Python syntax parse",
          status: "passed" as const,
          summary: "The reviewed Python AST parsed successfully without importing or executing the historical program.",
        }],
        publicProvider: false as const,
        targetContact: false as const,
        sourceExecution: false as const,
        isolatedLocalValidation: true as const,
        validatedAt,
      };
      return Object.freeze({
        ...material,
        receiptHash: digestCanonicalJson(material, {
          maxBytes: 1_048_576,
          maxDepth: 24,
        }).sha256,
      });
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  }
}
