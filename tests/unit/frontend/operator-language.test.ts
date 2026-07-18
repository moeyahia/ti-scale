import { describe, expect, test } from "bun:test";
import { formatOperatorCopy, operatorText } from "../../../src/lib/operatorLanguage";

describe("operator language formatter", () => {
  test("uses explicit structured facts for source, disclosure, target interaction, and risk", () => {
    const raw = "Dispatch VulnIntel via the exact reviewed vulnintel-nvd get_cve_details binding using an opaque reference to the top-ranked CVE from step 1, remaining strictly read-only.";
    const copy = formatOperatorCopy(raw, {
      kind: "plan",
      agent: "VulnIntel",
      target: "HTB 10.129.39.191",
      metadata: {
        operation: "cve_detail_lookup",
        source: { kind: "nvd" },
        integration: { serverId: "vulnintel-nvd", toolName: "get_cve_details", policyVerified: true },
        providerDisclosure: { providerClass: "public", mode: "identifier_only" },
        targetInteraction: "none",
        risk: "read_only",
        relatedStepOrdinal: 1,
      },
    });

    expect(copy.translation).toBe("cve_detail");
    expect(copy.displayText).toContain("Ask the VulnIntel specialist to review the NVD record");
    expect(copy.displayText).toContain("from step 1");
    expect(copy.displayText).toContain("policy-verified integration is vulnintel-nvd.get_cve_details");
    expect(copy.displayText).toContain("only the CVE identifier to be sent to the public provider");
    expect(copy.displayText).toContain("raw engagement data is excluded");
    expect(copy.displayText).toContain("records no interaction with HTB 10.129.39.191");
    expect(copy.displayText).toContain("risk classification is read-only");
    expect(copy.rawText).toBe(raw);
  });

  test("does not promote prose claims into safety, disclosure, or NVD provenance", () => {
    const raw = "Fetch public NVD detail for the top CVE candidate without target interaction using an opaque reference and remaining strictly read-only.";
    const copy = formatOperatorCopy(raw, {
      kind: "next_action",
      agent: "VulnIntel",
      target: "HTB 10.129.39.191",
      destructive: false,
    });

    expect(copy.translation).toBe("cve_detail");
    expect(copy.displayText).toContain("available vulnerability record");
    expect(copy.displayText).toContain("not verified by structured metadata");
    expect(copy.displayText).not.toContain("NVD record");
    expect(copy.displayText).not.toContain("public provider");
    expect(copy.displayText).not.toContain("read-only");
    expect(copy.displayText).not.toContain("no interaction with");
    expect(copy.displayText).not.toContain("does not contact");
    expect(copy.displayText).not.toContain("raw engagement data is excluded");
  });

  test("uses neutral search wording when prose names NVD without structured provenance", () => {
    const raw = "Search NVD for publicly known CVEs to prioritize the authorized assessment.";
    const copy = formatOperatorCopy(raw, { kind: "action_intent", agent: "VulnIntel" });

    expect(copy.translation).toBe("cve_search");
    expect(copy.displayText).toContain("available vulnerability catalog");
    expect(copy.displayText).toContain("does not confirm that any candidate affects the target");
    expect(copy.displayText).not.toContain("NVD catalog");
    expect(copy.displayText).not.toContain("public reference data");
    expect(copy.displayText).not.toContain("does not contact");
  });

  test("names NVD only when the structured source says NVD", () => {
    const copy = formatOperatorCopy("Search the approved source for related CVEs.", {
      kind: "action_intent",
      metadata: { operation: "cve_search", source: { kind: "nvd" } },
    });

    expect(copy.displayText).toContain("Search the NVD catalog");
    expect(copy.displayText).toContain("does not establish provider disclosure, target interaction, risk classification");
    expect(copy.displayText).not.toContain("public provider");
  });

  test("does not infer NVD provenance from CVE IDs or prose in a technical result", () => {
    const raw = '# NVD CVE search result\n\n找到 2 个相关漏洞\n\n| CVE ID | 描述 |\n| CVE-2025-0001 | A |\n| CVE-2025-0002 | B |';
    const copy = formatOperatorCopy(raw, { kind: "action_result" });

    expect(copy.displayText).toBe(
      "The recorded result contains 2 CVE references; structured metadata does not identify their source. These are not confirmed vulnerabilities on the target; applicability still requires matching product and version evidence.",
    );
    expect(copy.displayText).not.toContain("NVD");
    expect(copy.displayText).not.toContain("public");
    expect(copy.rawText).toBe(raw);
    expect(copy.translation).toBe("technical_result");
  });

  test("uses a structured result count and source when both are supplied", () => {
    const copy = formatOperatorCopy("CVE-2025-0001", {
      kind: "action_result",
      metadata: {
        source: { kind: "nvd" },
        result: { kind: "cve_candidates", count: 3 },
      },
    });

    expect(copy.displayText).toContain("structured NVD result contains 3 CVE candidates");
  });

  test("does not turn non-destructive or NVD-flavored error prose into a no-change claim", () => {
    const raw = "vulnintel-nvd MCP tool reported an error";
    const copy = formatOperatorCopy(raw, { kind: "action_result", destructive: false });

    expect(copy.displayText).toContain("recorded tool integration returned an error");
    expect(copy.displayText).toContain("Target effects and risk are not established by structured metadata");
    expect(copy.displayText).not.toContain("No change was made");
    expect(copy.displayText).not.toContain("read-only");
  });

  test("reports no target interaction and read-only risk only from structured facts", () => {
    const copy = formatOperatorCopy("MCP tool reported an error", {
      kind: "action_result",
      target: "HTB 10.129.39.191",
      metadata: {
        integration: { serverId: "local-vuln", toolName: "lookup", policyVerified: true },
        providerDisclosure: { providerClass: "local", mode: "none" },
        targetInteraction: "none",
        risk: "read_only",
      },
    });

    expect(copy.displayText).toContain("records no interaction with HTB 10.129.39.191");
    expect(copy.displayText).toContain("risk classification is read-only");
  });

  test("neutralizes opaque and read-only enum jargon without inventing guarantees", () => {
    const copy = formatOperatorCopy("Use an opaque reference with read_only_external_api_no_target_state_change.");
    expect(copy.displayText).toBe("Use a reference value with recorded external API operation.");
    expect(copy.displayText).not.toContain("raw engagement data");
    expect(copy.displayText).not.toContain("no target state changes");
  });

  test("leaves already readable operator prose semantically unchanged", () => {
    const raw = "Review the imported history before starting a new authorized run.";
    expect(formatOperatorCopy(raw)).toEqual({
      displayText: raw,
      rawText: raw,
      translated: false,
      translation: "none",
    });
    expect(operatorText(null, {}, "No next action reported")).toBe("No next action reported");
    expect(operatorText("Retrieve the approved service record", { kind: "plan" })).toBe("Retrieve the approved service record");
  });
});
