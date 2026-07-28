import { describe, expect, test } from "bun:test";
import {
  classifyGenericHistoricalRecord,
  evaluateGenericHistoricalKnowledgeQuality,
  hasGenericHistoricalReusableSourceBoundary,
  type GenericHistoricalKnowledgeSignals,
} from "../GenericHistoricalKnowledgeQualityGate";

const baseline: GenericHistoricalKnowledgeSignals = {
  productCount: 0,
  cveCount: 0,
  attackCount: 0,
  toolCount: 0,
  hasOperationalObservation: false,
  hasCveApplicability: false,
  hasFailedOutcome: false,
  hasWorkedOutcome: false,
  hasRecoveryAction: false,
  hasRecoverySequence: false,
};

describe("GenericHistoricalKnowledgeQualityGate", () => {
  test("keeps unbound operator provider archives as private custody only", () => {
    expect(hasGenericHistoricalReusableSourceBoundary({
      absolutePath: "/root/.codex/sessions/2026/07/21/rollout.jsonl",
      type: "provider_session_jsonl",
    })).toBeFalse();
    expect(hasGenericHistoricalReusableSourceBoundary({
      absolutePath: "/root/.grok/sessions/session.json",
      type: "provider_session_json",
    })).toBeFalse();
    expect(hasGenericHistoricalReusableSourceBoundary({
      absolutePath: "/var/lib/chillspwn/state/session-logs/runtime.jsonl",
      type: "raw_llm_jsonl",
    })).toBeTrue();
    expect(hasGenericHistoricalReusableSourceBoundary({
      absolutePath: "/root/.codex/sessions/notes.txt",
      type: "artifact",
    })).toBeTrue();
  });

  test("classifies provider prompts, streams, tool results, and structured records", () => {
    expect(classifyGenericHistoricalRecord({ role: "system", content: "example" }, "provider_session_jsonl"))
      .toBe("prompt_or_stream");
    expect(classifyGenericHistoricalRecord({
      type: "stream_event",
      event: { type: "text_delta", delta: "partial" },
    }, "raw_llm_jsonl")).toBe("prompt_or_stream");
    expect(classifyGenericHistoricalRecord({
      type: "response_item",
      payload: { type: "function_call_output", output: "complete" },
    }, "provider_session_jsonl")).toBe("tool_result");
    expect(classifyGenericHistoricalRecord({ status: "completed", result: "verified output" }, "run_json"))
      .toBe("structured_operational");
    expect(classifyGenericHistoricalRecord({ role: "assistant", content: "claim" }, "provider_session_jsonl"))
      .toBe("narrative");
  });

  test("rejects raw narrative and bare status or recovery words", () => {
    expect(evaluateGenericHistoricalKnowledgeQuality("narrative", {
      ...baseline,
      productCount: 1,
      attackCount: 1,
      hasWorkedOutcome: true,
    })).toEqual({
      accepted: false,
      reason: "non_evidentiary_narrative",
      retainOutcome: false,
      retainRecovery: false,
    });
    expect(evaluateGenericHistoricalKnowledgeQuality("structured_operational", {
      ...baseline,
      hasFailedOutcome: true,
      hasRecoveryAction: true,
      hasRecoverySequence: true,
    })).toEqual({
      accepted: false,
      reason: "insufficient_technical_context",
      retainOutcome: false,
      retainRecovery: false,
    });
  });

  test("retains stack evidence and only attributable outcomes and recoveries", () => {
    expect(evaluateGenericHistoricalKnowledgeQuality("tool_result", {
      ...baseline,
      productCount: 1,
      hasOperationalObservation: true,
    })).toEqual({ accepted: true, retainOutcome: false, retainRecovery: false });
    expect(evaluateGenericHistoricalKnowledgeQuality("structured_operational", {
      ...baseline,
      productCount: 1,
      attackCount: 1,
      toolCount: 1,
      hasFailedOutcome: true,
      hasRecoveryAction: true,
      hasRecoverySequence: true,
    })).toEqual({ accepted: true, retainOutcome: true, retainRecovery: true });
    expect(evaluateGenericHistoricalKnowledgeQuality("structured_operational", {
      ...baseline,
      productCount: 1,
      attackCount: 1,
      hasWorkedOutcome: true,
      hasRecoveryAction: true,
      hasRecoverySequence: true,
    })).toEqual({ accepted: true, retainOutcome: true, retainRecovery: false });
  });
});
