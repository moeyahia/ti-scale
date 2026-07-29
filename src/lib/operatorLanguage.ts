export type OperatorCopyKind =
  | "action_intent"
  | "action_result"
  | "event"
  | "next_action"
  | "plan"
  | "status";

export interface OperatorCopyContext {
  kind?: OperatorCopyKind;
  agent?: string | null;
  target?: string | null;
  /**
   * Compatibility hint retained for callers that still expose the plan action shape.
   * A non-destructive action is not necessarily read-only and may still
   * contact or change a target, so this value never authorizes safety copy.
   */
  destructive?: boolean;
  metadata?: OperatorCopyMetadata;
}

export interface OperatorCopyMetadata {
  operation?: "cve_detail_lookup" | "cve_search";
  source?: {
    kind: "nvd" | "cve_org" | "mitre" | "cisa" | "vendor" | "other";
    label?: string;
  };
  integration?: {
    serverId: string;
    toolName: string;
    policyVerified?: boolean;
  };
  providerDisclosure?: {
    providerClass: "public" | "private" | "local";
    mode: "identifier_only" | "sanitized" | "none" | "unknown";
  };
  targetInteraction?: "none" | "read" | "state_changing" | "unknown";
  risk?: "read_only" | "low" | "medium" | "high" | "critical" | "unknown";
  result?: {
    kind: "cve_candidates";
    count: number;
  };
  relatedStepOrdinal?: number;
}

export interface OperatorCopy {
  displayText: string;
  rawText: string;
  translated: boolean;
  translation: "cve_detail" | "cve_search" | "tool_error" | "technical_result" | "jargon" | "none";
}

function normalizedProse(value: string): string {
  return value.trim().replace(/[ \t]+/gu, " ").replace(/\s+([,.;:!?])/gu, "$1");
}

function result(rawText: string, displayText: string, translation: OperatorCopy["translation"]): OperatorCopy {
  const display = normalizedProse(displayText);
  return { displayText: display, rawText, translated: display !== rawText.trim(), translation };
}

function friendlyAgent(value: string | null | undefined): string | null {
  if (!value?.trim()) return null;
  if (/^vulnintel$/iu.test(value.trim())) return "VulnIntel specialist";
  if (/scout$/iu.test(value.trim())) return `${value.trim()} specialist`;
  return value.trim();
}

function actorFrom(context: OperatorCopyContext): string | null {
  return friendlyAgent(context.agent);
}

function sourceLabel(metadata: OperatorCopyMetadata | undefined): string | null {
  if (!metadata?.source) return null;
  if (metadata.source.kind === "nvd") return "NVD";
  const label = metadata.source.label?.trim();
  return label || metadata.source.kind.replaceAll("_", " ").toLocaleUpperCase("en-US");
}

function referencedStep(metadata: OperatorCopyMetadata | undefined): string {
  const ordinal = metadata?.relatedStepOrdinal;
  return Number.isSafeInteger(ordinal) && (ordinal ?? 0) > 0 ? ` from step ${ordinal}` : "";
}

function metadataSentences(context: OperatorCopyContext): string[] {
  const metadata = context.metadata;
  if (!metadata) {
    return ["Source, provider disclosure, target interaction, and risk are not verified by structured metadata; review the technical detail before relying on those claims."];
  }
  const sentences: string[] = [];
  const unknown: string[] = [];
  if (!metadata.source) unknown.push("source provenance");
  if (metadata.integration) {
    const policy = metadata.integration.policyVerified === true ? "policy-verified " : "recorded ";
    sentences.push(`The ${policy}integration is ${metadata.integration.serverId}.${metadata.integration.toolName}.`);
  }
  if (!metadata.providerDisclosure || metadata.providerDisclosure.mode === "unknown") {
    unknown.push("provider disclosure");
  } else if (metadata.providerDisclosure.providerClass === "public" && metadata.providerDisclosure.mode === "identifier_only") {
    sentences.push("The structured disclosure policy permits only the CVE identifier to be sent to the public provider; raw engagement data is excluded.");
  } else if (metadata.providerDisclosure.providerClass === "public" && metadata.providerDisclosure.mode === "sanitized") {
    sentences.push("The structured disclosure policy permits only sanitized context to be sent to the public provider.");
  } else if (metadata.providerDisclosure.mode === "none") {
    sentences.push("The structured disclosure policy records no provider disclosure for this action.");
  } else {
    sentences.push(`The structured disclosure policy classifies this as ${metadata.providerDisclosure.providerClass} provider use.`);
  }
  const target = context.target?.trim() || "the mission target";
  if (!metadata.targetInteraction || metadata.targetInteraction === "unknown") {
    unknown.push("target interaction");
  } else if (metadata.targetInteraction === "none") {
    sentences.push(`The structured action metadata records no interaction with ${target}.`);
  } else if (metadata.targetInteraction === "read") {
    sentences.push(`The structured action metadata permits reading from ${target}.`);
  } else {
    sentences.push(`The structured action metadata permits state-changing interaction with ${target}.`);
  }
  if (!metadata.risk || metadata.risk === "unknown") {
    unknown.push("risk classification");
  } else {
    sentences.push(`The recorded risk classification is ${metadata.risk.replaceAll("_", "-")}.`);
  }
  if (unknown.length > 0) {
    sentences.push(`Structured metadata does not establish ${unknown.join(", ")}; review the technical detail before relying on those claims.`);
  }
  return sentences;
}

function cveDetailCopy(rawText: string, context: OperatorCopyContext): OperatorCopy | null {
  const structured = context.metadata?.operation === "cve_detail_lookup";
  const isDetail = /get_cve_details|\b(?:fetch|obtain|retrieve|review)\b[^.]{0,90}\b(?:CVE\s+)?details?\b|\bdetail\s+(?:enrichment|lookup|record)\b/iu.test(rawText);
  const isActionable = context.kind === "action_intent" || context.kind === "next_action"
    || /^(?:Dispatch|Fetch|Obtain|Retrieve|Review)\b|\bget_cve_details\s+binding\b/iu.test(rawText);
  if (!(structured || (isDetail && isActionable))) return null;

  const actor = actorFrom(context);
  const source = sourceLabel(context.metadata);
  const record = source ? `${source} record` : "available vulnerability record";
  const what = `${actor ? `Ask the ${actor} to review` : "Review"} the ${record} for the selected CVE candidate${referencedStep(context.metadata)}.`;
  const goal = "Use its affected-product, severity, and reference details to decide whether the candidate merits version-aware validation.";
  return result(rawText, `${what} ${goal} ${metadataSentences(context).join(" ")}`, "cve_detail");
}

function cveSearchCopy(rawText: string, context: OperatorCopyContext): OperatorCopy | null {
  const structured = context.metadata?.operation === "cve_search";
  const isSearch = /search_cves|\b(?:search|query|enumerate|collect)\b[^.]{0,100}\bCVEs?\b|\bCVE\s+(?:search|candidates?|records?)\b/iu.test(rawText);
  const isActionable = context.kind === "action_intent" || context.kind === "next_action"
    || /^(?:Dispatch|Search|Query|Enumerate|Collect)\b|\bsearch_cves\s+binding\b/iu.test(rawText);
  if (!(structured || (isSearch && isActionable))) return null;

  const actor = actorFrom(context);
  const source = sourceLabel(context.metadata);
  const catalog = source ? `${source} catalog` : "available vulnerability catalog";
  const what = `${actor ? `Ask the ${actor} to search` : "Search"} the ${catalog} for CVEs related to the mission's current technical hypotheses.`;
  const why = "This creates a shortlist for prioritization; it does not confirm that any candidate affects the target until product and version evidence match.";
  return result(rawText, `${what} ${why} ${metadataSentences(context).join(" ")}`, "cve_search");
}

function technicalCveResult(rawText: string, context: OperatorCopyContext): OperatorCopy | null {
  const ids = new Set(rawText.match(/CVE-\d{4}-\d{4,}/gu) ?? []);
  const structuredResult = context.metadata?.result?.kind === "cve_candidates" ? context.metadata.result : null;
  const count = structuredResult?.count ?? ids.size;
  if (!Number.isSafeInteger(count) || count < 1) return null;
  const source = sourceLabel(context.metadata);
  const provenance = source
    ? `The structured ${source} result contains ${count} CVE candidate${count === 1 ? "" : "s"}.`
    : `The recorded result contains ${count} CVE reference${count === 1 ? "" : "s"}; structured metadata does not identify their source.`;
  return result(
    rawText,
    `${provenance} These are not confirmed vulnerabilities on the target; applicability still requires matching product and version evidence.`,
    "technical_result",
  );
}

function toolErrorCopy(rawText: string, context: OperatorCopyContext): OperatorCopy | null {
  if (!/\b(?:MCP|tool|integration)\b[^.\n]{0,80}\b(?:error|failed|failure)\b|\bHTTP\s+Error\s+\d{3}\b/iu.test(rawText)) return null;
  const verified = context.metadata?.integration?.policyVerified === true ? "policy-verified" : "recorded";
  const boundaries = context.metadata ? metadataSentences(context).join(" ") : "Target effects and risk are not established by structured metadata.";
  return result(rawText, `The ${verified} tool integration returned an error, so the intended action did not complete. ${boundaries} Open the technical detail for the exact response before retrying.`, "tool_error");
}

function replaceKnownJargon(rawText: string): OperatorCopy {
  let displayText = normalizedProse(rawText)
    .replace(/\buser[- ]flag and root[- ]flag objectives\b/giu, "user and root objectives")
    .replace(/\buser and root flag capture\b/giu, "the user and root objectives")
    .replace(/\bflag-oriented (?:work|prioritization)\b/giu, "mission-objective prioritization")
    .replace(/\bexact reviewed\b/giu, "approved")
    .replace(/\breviewed\s+([A-Za-z][\w-]*\s+)?NVD bindings?\b/giu, "approved $1NVD integrations")
    .replace(/\breviewed executable surface\b/giu, "approved tool set")
    .replace(/\breviewed tool bindings?\b/giu, "approved tool integrations")
    .replace(/\breviewed tool path\b/giu, "approved tool route")
    .replace(/\btool evidence path\b/giu, "approved tool workflow")
    .replace(/\ban opaque step result reference\b/giu, "a reference returned by the previous step")
    .replace(/\bopaque step result reference\b/giu, "reference returned by the previous step")
    .replace(/\ban opaque reference\b/giu, "a reference value")
    .replace(/\bopaque reference\b/giu, "reference value")
    .replace(/\bmutate the (?:lab )?target\b/giu, "change the target")
    .replace(/\bmutating the (?:lab )?target\b/giu, "changing the target")
    .replace(/\bthe in-contract path\b/giu, "the path permitted by the signed contract")
    .replace(/\bin-contract replans?\b/giu, "replanning within the signed contract")
    .replace(/\bin-contract\b/giu, "within the signed contract")
    .replace(/\btarget-exact\b/giu, "limited to the authorized target")
    .replace(/\bis acyclic read-only vulnerability intelligence\b/giu, "is a vulnerability-intelligence workflow with no circular dependencies")
    .replace(/\bacyclic\b/giu, "free of circular dependencies")
    .replace(/\bprovider-only analysis\b/giu, "analysis by the reasoning model")
    .replace(/\bcapability gaps?\b/giu, "missing required capabilities")
    .replace(/\bAutonomous forbids manual operator steps\b/gu, "Autonomous execution cannot rely on manual operator steps")
    .replace(/\bno exploitation specialist is inventoried\b/giu, "no exploitation specialist is currently available")
    .replace(/\bfully_reversible_read_only_query\b/gu, "recorded query operation")
    .replace(/\bread_only_external_api_no_target_state_change\b/gu, "recorded external API operation")
    .replace(/\banalysis_only_no_state_change\b/gu, "recorded analysis operation");
  displayText = displayText.replace(/\bDispatch\s+([A-Za-z][\w-]*)\b/gu, "Ask the $1 specialist to handle this step");
  return result(rawText, displayText, displayText === rawText.trim() ? "none" : "jargon");
}

/**
 * Converts persisted runtime prose into concise operator language without changing
 * the canonical value. Callers must retain `rawText` in their technical detail.
 */
export function formatOperatorCopy(value: string | null | undefined, context: OperatorCopyContext = {}): OperatorCopy {
  const rawText = value?.trim() ?? "";
  if (!rawText) return { displayText: "", rawText, translated: false, translation: "none" };

  if (context.kind === "action_result") {
    const technical = technicalCveResult(rawText, context);
    if (technical) return technical;
    const error = toolErrorCopy(rawText, context);
    if (error) return error;
  }
  return cveDetailCopy(rawText, context)
    ?? cveSearchCopy(rawText, context)
    ?? toolErrorCopy(rawText, context)
    ?? replaceKnownJargon(rawText);
}

export function operatorText(value: string | null | undefined, context: OperatorCopyContext = {}, fallback = "Not reported"): string {
  const copy = formatOperatorCopy(value, context);
  return copy.displayText || fallback;
}
