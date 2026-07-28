import { describe, expect, test } from "bun:test";
import {
  LOCAL_RELEASE_ATTESTATION,
  PLAYWRIGHT_MANAGED_STATIC_SERVER_MODE,
  parseE2EProfile,
} from "../../e2e/support/e2eProfile";

const releaseEnvironment = (overrides: Record<string, string | undefined> = {}) => ({
  TI_SCALE_E2E_PROFILE: "release",
  TI_SCALE_E2E_REQUIRE_API: "1",
  TI_SCALE_E2E_ENFORCE_MANIFEST: "1",
  TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS: "1",
  TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY: "1",
  TI_SCALE_E2E_SERVER_MODE: PLAYWRIGHT_MANAGED_STATIC_SERVER_MODE,
  TI_SCALE_E2E_EXTERNAL_SERVERS: "false",
  TI_SCALE_E2E_BASE_URL: "http://127.0.0.1:43141",
  TI_SCALE_E2E_API_URL: "http://127.0.0.1:43141",
  TI_SCALE_E2E_CANDIDATE_SHA: "a".repeat(40),
  ...overrides,
});

describe("E2E execution profile parser", () => {
  test("preserves strict development defaults and explicit degraded relaxation", () => {
    expect(parseE2EProfile({})).toEqual(expect.objectContaining({
      profile: "development",
      requireApi: true,
      enforceManifest: false,
      baseURL: "http://127.0.0.1:43140",
      apiURL: "http://127.0.0.1:43141",
      releaseAttestation: undefined,
    }));
    expect(parseE2EProfile({ TI_SCALE_E2E_PROFILE: "development" }).requireApi).toBe(true);
    expect(parseE2EProfile({
      TI_SCALE_E2E_PROFILE: " development ",
      TI_SCALE_E2E_REQUIRE_API: " 0 ",
    }).requireApi).toBe(true);
    expect(parseE2EProfile({
      TI_SCALE_E2E_PROFILE: "degraded",
      TI_SCALE_E2E_REQUIRE_API: "0",
    })).toEqual(expect.objectContaining({
      profile: "degraded",
      requireApi: false,
      releaseAttestation: undefined,
    }));
    expect(parseE2EProfile({ TI_SCALE_E2E_PROFILE: "degraded" }).requireApi).toBe(false);
  });

  test("keeps degraded as the only profile that may relax required API auditing", () => {
    expect(() => parseE2EProfile({
      TI_SCALE_E2E_PROFILE: "development",
      TI_SCALE_E2E_REQUIRE_API: "0",
    })).toThrow("Required V2 API auditing can be relaxed only by the explicit degraded profile");
    expect(() => parseE2EProfile({
      TI_SCALE_E2E_PROFILE: "release",
      TI_SCALE_E2E_REQUIRE_API: "0",
    })).toThrow("Required V2 API auditing can be relaxed only by the explicit degraded profile");
    expect(() => parseE2EProfile({ TI_SCALE_E2E_PROFILE: "smoke" })).toThrow(
      "TI_SCALE_E2E_PROFILE must be development, release, or degraded",
    );
  });

  test("uses only the canonical E2E manifest switch outside release", () => {
    expect(parseE2EProfile({
      TI_SCALE_E2E_PROFILE: "development",
      TI_SCALE_E2E_ENFORCE_MANIFEST: "1",
    }).enforceManifest).toBe(true);
    expect(parseE2EProfile({
      TI_SCALE_E2E_PROFILE: "development",
      TI_SCALE_ENFORCE_MANIFEST: "1",
    }).enforceManifest).toBe(false);
  });

  test("accepts only the exact managed-static release contract", () => {
    const parsed = parseE2EProfile(releaseEnvironment());
    expect(parsed).toEqual({
      profile: "release",
      requireApi: true,
      enforceManifest: true,
      serverMode: PLAYWRIGHT_MANAGED_STATIC_SERVER_MODE,
      externalServers: false,
      baseURL: "http://127.0.0.1:43141",
      apiURL: "http://127.0.0.1:43141",
      releaseAttestation: LOCAL_RELEASE_ATTESTATION,
    });
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  test("rejects every missing or relaxed release switch", () => {
    const cases: Array<[string, Record<string, string | undefined>, string]> = [
      ["required API", { TI_SCALE_E2E_REQUIRE_API: undefined }, "TI_SCALE_E2E_REQUIRE_API must equal \"1\""],
      ["exact required API", { TI_SCALE_E2E_REQUIRE_API: " 1 " }, "TI_SCALE_E2E_REQUIRE_API must equal \"1\""],
      ["manifest", { TI_SCALE_E2E_ENFORCE_MANIFEST: "0" }, "TI_SCALE_E2E_ENFORCE_MANIFEST must equal \"1\""],
      [
        "activation receipts",
        { TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS: undefined },
        "TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS must equal \"1\"",
      ],
      [
        "release result policy",
        { TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY: undefined },
        "TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY must equal \"1\"",
      ],
      ["server", { TI_SCALE_E2E_SERVER_MODE: "vite-development" }, "TI_SCALE_E2E_SERVER_MODE must equal \"playwright-managed-static\""],
      ["external server", { TI_SCALE_E2E_EXTERNAL_SERVERS: "true" }, "TI_SCALE_E2E_EXTERNAL_SERVERS must equal \"false\""],
      ["missing external declaration", { TI_SCALE_E2E_EXTERNAL_SERVERS: undefined }, "TI_SCALE_E2E_EXTERNAL_SERVERS must equal \"false\""],
      ["missing UI URL", { TI_SCALE_E2E_BASE_URL: undefined }, "TI_SCALE_E2E_BASE_URL must be explicitly set"],
      ["missing API URL", { TI_SCALE_E2E_API_URL: undefined }, "TI_SCALE_E2E_API_URL must be explicitly set"],
      [
        "missing candidate",
        { TI_SCALE_E2E_CANDIDATE_SHA: undefined },
        "TI_SCALE_E2E_CANDIDATE_SHA must be the exact lowercase 40-character checked-out Git commit",
      ],
      [
        "invalid candidate",
        { TI_SCALE_E2E_CANDIDATE_SHA: "not-a-git-commit" },
        "TI_SCALE_E2E_CANDIDATE_SHA must be the exact lowercase 40-character checked-out Git commit",
      ],
    ];
    for (const [, overrides, expectedMessage] of cases) {
      expect(() => parseE2EProfile(releaseEnvironment(overrides))).toThrow(expectedMessage);
    }
  });

  test("requires one credential-free loopback HTTP origin for UI and API", () => {
    const cases: Array<[Record<string, string>, string]> = [
      [{ TI_SCALE_E2E_API_URL: "http://127.0.0.1:43142" }, "must have the same origin"],
      [{
        TI_SCALE_E2E_BASE_URL: "https://127.0.0.1:43141",
        TI_SCALE_E2E_API_URL: "https://127.0.0.1:43141",
      }, "must use local HTTP"],
      [{
        TI_SCALE_E2E_BASE_URL: "http://example.test:43141",
        TI_SCALE_E2E_API_URL: "http://example.test:43141",
      }, "must use a loopback host"],
      [{
        TI_SCALE_E2E_BASE_URL: "http://operator:secret@127.0.0.1:43141",
        TI_SCALE_E2E_API_URL: "http://operator:secret@127.0.0.1:43141",
      }, "must not contain URL credentials"],
    ];
    for (const [overrides, expectedMessage] of cases) {
      expect(() => parseE2EProfile(releaseEnvironment(overrides))).toThrow(expectedMessage);
    }

    expect(parseE2EProfile(releaseEnvironment({
      TI_SCALE_E2E_BASE_URL: "http://localhost:43141",
      TI_SCALE_E2E_API_URL: "http://localhost:43141/api/v2",
    })).profile).toBe("release");
    expect(parseE2EProfile(releaseEnvironment({
      TI_SCALE_E2E_BASE_URL: "http://[::1]:43141",
      TI_SCALE_E2E_API_URL: "http://[::1]:43141",
    })).profile).toBe("release");
  });

  test("freezes an explicitly ineligible local release attestation", () => {
    expect(LOCAL_RELEASE_ATTESTATION).toEqual(expect.objectContaining({
      immutableSourceAttested: false,
      releaseCandidateEligible: false,
    }));
    expect(LOCAL_RELEASE_ATTESTATION.blockers.length).toBeGreaterThanOrEqual(3);
    expect(Object.isFrozen(LOCAL_RELEASE_ATTESTATION)).toBe(true);
    expect(Object.isFrozen(LOCAL_RELEASE_ATTESTATION.blockers)).toBe(true);
  });
});
