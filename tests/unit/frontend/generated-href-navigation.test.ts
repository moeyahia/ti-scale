import { describe, expect, test } from "bun:test";
import { classifyGeneratedHrefNavigation } from "../../e2e/support/routes";

describe("generated internal href navigation classification", () => {
  test("requires a document request for path, query, or origin changes", () => {
    expect(classifyGeneratedHrefNavigation(
      "http://127.0.0.1:43142/agents/ADAttackMapper",
      "/agents/CloudSentinel",
    )).toBe("document");
    expect(classifyGeneratedHrefNavigation(
      "http://127.0.0.1:43142/brain/graph",
      "/brain/graph?view=operator",
    )).toBe("document");
    expect(classifyGeneratedHrefNavigation(
      "http://127.0.0.1:43142/agents/ADAttackMapper",
      "http://127.0.0.1:43143/agents/ADAttackMapper",
    )).toBe("document");
  });

  test("recognizes fragment changes as same-document navigation", () => {
    expect(classifyGeneratedHrefNavigation(
      "http://127.0.0.1:43142/agents/ADAttackMapper",
      "/agents/ADAttackMapper#agent-model-configuration",
    )).toBe("same-document");
    expect(classifyGeneratedHrefNavigation(
      "http://127.0.0.1:43142/agents/ADAttackMapper#agent-model-configuration",
      "/agents/ADAttackMapper",
    )).toBe("same-document");
  });

  test("recognizes an exact repeated URL without weakening other navigation checks", () => {
    expect(classifyGeneratedHrefNavigation(
      "http://127.0.0.1:43142/agents/ADAttackMapper#agent-model-configuration",
      "/agents/ADAttackMapper#agent-model-configuration",
    )).toBe("duplicate");
  });
});
