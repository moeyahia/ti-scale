import type {
  GuidedCommanderPort,
  GuidedCommanderPortInput,
  GuidedCommanderPortResponse,
} from "./types";
import { buildGuidedCommanderProviderPrompt } from "./GuidedCommanderProviderContract";
import { GuidedCommanderError, validatePortResponse } from "./validation";

export interface GrokGuidedCommanderPortOptions {
  readonly callGrok: (prompt: string, signal: AbortSignal) => Promise<string>;
  readonly model?: string;
  readonly maximumResponseBytes?: number;
}

const DEFAULT_MAXIMUM_RESPONSE_BYTES = 64 * 1024;
/** OAuth-backed Grok ACP adapter with a JSON-only, planning-only surface. */
export class GrokGuidedCommanderPort implements GuidedCommanderPort {
  readonly kind = "planning_only" as const;
  readonly supportsToolExecution = false as const;
  readonly contextBoundary = "public_provider" as const;
  readonly providerId = "grok-acp-oauth";
  readonly model: string;
  readonly #callGrok: GrokGuidedCommanderPortOptions["callGrok"];
  readonly #maximumResponseBytes: number;

  constructor(options: GrokGuidedCommanderPortOptions) {
    if (typeof options.callGrok !== "function") throw new TypeError("callGrok is required");
    this.#callGrok = options.callGrok;
    this.model = options.model?.trim() || "grok-4.5";
    this.#maximumResponseBytes = options.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES;
    if (
      !Number.isSafeInteger(this.#maximumResponseBytes) ||
      this.#maximumResponseBytes < 1_024 ||
      this.#maximumResponseBytes > 1024 * 1024
    ) {
      throw new RangeError("maximumResponseBytes must be 1 KiB through 1 MiB");
    }
  }

  async respond(
    input: GuidedCommanderPortInput,
    signal: AbortSignal,
  ): Promise<GuidedCommanderPortResponse> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const raw = await this.#callGrok(buildGuidedCommanderProviderPrompt(input), signal);
    if (Buffer.byteLength(raw, "utf8") > this.#maximumResponseBytes) {
      throw new GuidedCommanderError(502, "guided_commander_response_too_large", "Grok response exceeded the JSON boundary", {
        humanMessage: "The explanation provider returned too much data and nothing was persisted as a response.",
        category: "provider_unavailable",
        retryable: true,
      });
    }
    const source = raw.trim();
    if (!source.startsWith("{") || !source.endsWith("}") || source.includes("```")) {
      throw new GuidedCommanderError(502, "guided_commander_json_required", "Grok response was not a plain JSON object", {
        humanMessage: "The explanation provider did not honor the strict JSON response contract.",
        category: "provider_unavailable",
        retryable: true,
      });
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(source) as unknown;
    } catch {
      throw new GuidedCommanderError(502, "guided_commander_json_invalid", "Grok response contained invalid JSON", {
        humanMessage: "The explanation provider returned malformed JSON and no response was persisted.",
        category: "provider_unavailable",
        retryable: true,
      });
    }
    return validatePortResponse(parsed);
  }
}

export function createGrokGuidedCommanderPort(
  options: GrokGuidedCommanderPortOptions,
): GrokGuidedCommanderPort {
  return new GrokGuidedCommanderPort(options);
}
