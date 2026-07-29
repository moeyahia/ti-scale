import { describe, expect, test } from "bun:test";
import { requiredSafeReason, sanitizeJson, sanitizeJsonWithRedaction } from "../validation";

describe("operations projection redaction", () => {
  test("combines known-secret defense with bounded producer-declared paths", () => {
    expect(sanitizeJsonWithRedaction({
      credential: "do-not-project",
      opaque: { nested: "also-do-not-project", retained: "safe semantic value" },
    }, {
      paths: ["opaque.nested"],
    })).toEqual({
      credential: "[REDACTED]",
      opaque: { nested: "[REDACTED]", retained: "safe semantic value" },
    });
  });

  test("redacts camelCase authentication keys and rejects camelCase token assignments", () => {
    expect(sanitizeJson({
      apiToken: "must-not-project",
      clientSecret: "must-not-project",
      nested: { refreshToken: "must-not-project", retained: "safe semantic value" },
    })).toEqual({
      apiToken: "[REDACTED]",
      clientSecret: "[REDACTED]",
      nested: { refreshToken: "[REDACTED]", retained: "safe semantic value" },
    });

    expect(() => requiredSafeReason("apiToken=must-not-enter-audit", "Reason"))
      .toThrow("Sensitive material was rejected");
  });
});
