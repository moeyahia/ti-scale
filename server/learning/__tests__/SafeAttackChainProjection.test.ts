import { describe, expect, test } from "bun:test";
import {
  findRejectableSecrets,
  findReusableContentIdentifiers,
} from "../AttackLesson";
import { projectSafeAttackChain } from "../SafeAttackChainProjection";

function reusableText(result: ReturnType<typeof projectSafeAttackChain>): string {
  return [
    ...result.orderedSteps,
    ...result.tools,
    ...result.antiReuseWarnings,
  ].join("\n");
}

describe("projectSafeAttackChain", () => {
  test("retains structured option semantics while quarantining literal execution values", () => {
    const result = projectSafeAttackChain({
      fallbackDomain: "reconnaissance",
      actions: [{
        id: "action-safe-projection",
        actionType: "tool",
        actionClass: "reconnaissance",
        normalizedArgumentsJson: JSON.stringify({
          input: {
            mcpServer: "authorized-recon",
            toolName: "nmap",
            arguments: {
              target: "10.10.10.10",
              ports: [80, 443],
              flags: ["-sV", "-sC"],
              outputPath: "/tmp/CredSmith-scan.txt",
              username: "administrator",
              password: "S3cret-do-not-retain",
              command: "nmap -sV -sC -p 80,443 10.10.10.10 -oN /tmp/CredSmith-scan.txt",
              note: "HackTheBox CredSmith walkthrough material must not survive",
            },
          },
          orchestration: {
            target: "credsmith.htb",
            kind: "tool",
            idempotent: true,
          },
        }),
      }],
      toolCalls: [{
        id: "tool-call-safe-projection",
        actionId: "action-safe-projection",
        toolName: "nmap",
        normalizedArgumentsJson: JSON.stringify({
          host: "10.10.10.10",
          ports: "80,443",
          versionDetection: true,
          defaultScripts: true,
          wordlist: "/root/engagements/CredSmith/users.txt",
          token: "token-do-not-retain",
        }),
      }],
    });

    expect(result.tools).toEqual(["nmap"]);
    expect(result.publicReferences).toEqual(["https://nmap.org/book/man.html"]);
    expect(result.orderedSteps).toHaveLength(1);
    expect(result.orderedSteps[0]).toContain("<TARGET_HOST>");
    expect(result.orderedSteps[0]).toContain("<PORTS>");
    expect(result.orderedSteps[0]).toContain("<OUTPUT_PATH>");
    expect(result.orderedSteps[0]).toContain("<WORDLIST_PATH>");
    expect(result.orderedSteps[0]).toContain("<USER_REF>");
    expect(result.orderedSteps[0]).toContain("<CREDENTIAL_REF>");
    expect(result.orderedSteps[0]).toContain("service and version detection (-sV)");
    expect(result.orderedSteps[0]).toContain("default safe script set (-sC)");
    expect(result.orderedSteps[0]).toContain("immutable evidence");

    const text = reusableText(result);
    for (const forbidden of [
      "10.10.10.10", "credsmith", "hackthebox", "htb", "administrator",
      "S3cret", "token-do-not-retain", "/tmp", "/root", "nmap -sV -sC -p",
    ]) {
      expect(text.toLocaleLowerCase("en-US")).not.toContain(forbidden.toLocaleLowerCase("en-US"));
    }
    expect(result.orderedSteps.join("\n")).not.toMatch(/(?:^|\n)\s*(?:nmap|sudo|bash|sh)\s+/iu);
    expect(findRejectableSecrets(text)).toEqual([]);
    expect(findReusableContentIdentifiers(text)).toEqual([]);

    const reasons = new Set(result.quarantined.flatMap((entry) => entry.reasons));
    expect(reasons).toContain("target_value");
    expect(reasons).toContain("target_or_box_identity");
    expect(reasons).toContain("path_value");
    expect(reasons).toContain("identity_value");
    expect(reasons).toContain("credential_value");
    expect(reasons).toContain("raw_command");
    expect(result.quarantined.some((entry) => entry.sourceType === "action")).toBe(true);
    expect(result.quarantined.some((entry) => entry.sourceType === "tool_call")).toBe(true);
  });

  test("quarantines malformed and oversized canonical argument payloads without retaining them", () => {
    const oversized = JSON.stringify({ notes: "x".repeat(129 * 1024) });
    const result = projectSafeAttackChain({
      fallbackDomain: "analysis",
      actions: [{
        id: "action-malformed",
        actionType: "analysis",
        actionClass: "analysis",
        normalizedArgumentsJson: "{not-json:/root/engagements/CredSmith}",
      }],
      toolCalls: [{
        id: "tool-call-oversized",
        actionId: "action-malformed",
        toolName: "nmap",
        normalizedArgumentsJson: oversized,
      }],
    });

    expect(result.orderedSteps).toEqual([
      "Use nmap through the assigned specialist for bounded analysis against <TARGET_HOST>. Bind reviewed parameters at execution time. Retain the result as immutable evidence before advancing.",
    ]);
    expect(result.quarantined).toEqual([
      { sourceType: "action", sourceId: "action-malformed", reasons: ["malformed_json"] },
      { sourceType: "tool_call", sourceId: "tool-call-oversized", reasons: ["oversized_arguments"] },
    ]);
    expect(reusableText(result)).not.toContain("CredSmith");
  });

  test("extracts allowlisted flag meaning from a command-shaped argument but never retains the command", () => {
    const result = projectSafeAttackChain({
      fallbackDomain: "reconnaissance",
      actions: [{
        id: "action-command-shaped-args",
        actionType: "tool",
        actionClass: "reconnaissance",
        normalizedArgumentsJson: JSON.stringify({
          toolName: "nmap",
          args: "nmap -sV -sC 10.10.10.10 -oN /tmp/CredSmith.txt",
        }),
      }],
      toolCalls: [],
    });

    const text = reusableText(result);
    expect(result.orderedSteps[0]).toContain("service and version detection (-sV)");
    expect(result.orderedSteps[0]).toContain("default safe script set (-sC)");
    expect(text).not.toMatch(/10\.10\.10\.10|CredSmith|\/tmp|nmap -sV/iu);
    const reasons = new Set(result.quarantined.flatMap((entry) => entry.reasons));
    expect(reasons).toContain("raw_command");
    expect(reasons).toContain("path_value");
    expect(reasons).toContain("target_or_box_identity");
  });

  test("never promotes an unknown tool label or unsafe source field into reusable text", () => {
    const result = projectSafeAttackChain({
      fallbackDomain: "post exploitation for CredSmith",
      actions: [{
        id: "action-unknown-tool",
        actionType: "tool",
        actionClass: "post exploitation for CredSmith",
        normalizedArgumentsJson: JSON.stringify({
          toolName: "Administrator",
          file: "C:\\Users\\Administrator\\Desktop\\user.txt",
          target: "secretbox.htb",
          rawCommand: "powershell -enc do-not-retain",
        }),
      }],
      toolCalls: [],
    });

    expect(result.tools).toEqual(["specialist-procedure"]);
    expect(result.publicReferences).toEqual(["https://owasp.org/www-project-web-security-testing-guide/"]);
    const text = reusableText(result);
    expect(text).not.toMatch(/administrator|credsmith|secretbox|powershell|C:\\Users/iu);
    expect(text).toContain("<INPUT_PATH>");
    expect(text).toContain("<TARGET_HOST>");
    expect(findRejectableSecrets(text)).toEqual([]);
    expect(findReusableContentIdentifiers(text)).toEqual([]);
  });
});
