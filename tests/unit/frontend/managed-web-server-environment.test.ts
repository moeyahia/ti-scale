import { describe, expect, test } from "bun:test";
import { managedWebServerEnvironment } from "../../e2e/support/managedWebServerEnvironment";
import {
  E2E_DATA_ROOT,
  assertManagedE2EFixturePath,
  assertManagedE2EInvocationPaths,
} from "../../e2e/support/environment";
import {
  assertManagedE2EParentEnvironmentSafe,
  managedE2EChildEnvironment,
} from "../../../scripts/managed-e2e-child-environment";
import { playwrightChildEnvironment } from "../../../scripts/playwright-child-environment";

describe("Playwright managed web-server report hygiene", () => {
  test("returns only explicit report-safe overrides", () => {
    const environment = managedWebServerEnvironment({
      TI_SCALE_PORT: "43141",
      TI_SCALE_OPERATOR_TOKEN_FILE: "/tmp/ti-scale-e2e-data/operator-token-safe-fixture",
      TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE:
        "/tmp/ti-scale-e2e-data/research-integrity-key-safe-fixture",
      TI_SCALE_E2E_RUN_ID: "safe-fixture",
      TI_SCALE_E2E_STATIC_BUILD_ID: "e2e-safe-fixture-12345",
      TI_SCALE_PROVIDER_CONFIG_ROOT: "/tmp/ti-scale-e2e-data/provider-config-safe-fixture",
      TI_SCALE_SCRIPT_SOURCE_ROOT: "/tmp/ti-scale-e2e-data/ti-scale-script-sources-safe-fixture",
      OPTIONAL_UNDEFINED_VALUE: undefined,
    });
    expect(environment).toEqual({
      TI_SCALE_PORT: "43141",
      TI_SCALE_OPERATOR_TOKEN_FILE: "/tmp/ti-scale-e2e-data/operator-token-safe-fixture",
      TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE:
        "/tmp/ti-scale-e2e-data/research-integrity-key-safe-fixture",
      TI_SCALE_E2E_RUN_ID: "safe-fixture",
      TI_SCALE_E2E_STATIC_BUILD_ID: "e2e-safe-fixture-12345",
      TI_SCALE_PROVIDER_CONFIG_ROOT: "/tmp/ti-scale-e2e-data/provider-config-safe-fixture",
      TI_SCALE_SCRIPT_SOURCE_ROOT: "/tmp/ti-scale-e2e-data/ti-scale-script-sources-safe-fixture",
    });
    expect(Object.isFrozen(environment)).toBe(true);
  });

  test("rejects an inherited secret spread instead of serializing it", () => {
    expect(() => managedWebServerEnvironment({
      TI_SCALE_PORT: "43141",
      GITHUB_TOKEN: "must-never-enter-a-playwright-report",
    })).toThrow("not report-safe: GITHUB_TOKEN");
    expect(() => managedWebServerEnvironment({
      TI_SCALE_OPERATOR_TOKEN: "must-never-enter-a-playwright-report",
    })).toThrow("not report-safe: TI_SCALE_OPERATOR_TOKEN");
    expect(() => managedWebServerEnvironment({
      TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY:
        "must-never-enter-a-playwright-report",
    })).toThrow(
      "not report-safe: TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY",
    );
  });

  test("passes only the explicit child allowlist and rejects live provider credentials", () => {
    expect(managedE2EChildEnvironment({
      PATH: "/reviewed/bin",
      HOME: "/tmp/e2e-home",
      TI_SCALE_DATABASE_PATH: "/tmp/e2e.sqlite",
      TI_SCALE_OPERATOR_TOKEN_FILE: "/tmp/operator-token",
      TI_SCALE_SCRIPT_SOURCE_ROOT: "/tmp/ti-scale-script-sources",
      OPENROUTER_API_KEY: "canary-must-not-reach-child",
      UNRELATED_CANARY_SECRET: "canary-must-not-reach-child",
    })).toEqual({
      PATH: "/reviewed/bin",
      HOME: "/tmp/e2e-home",
      TI_SCALE_DATABASE_PATH: "/tmp/e2e.sqlite",
      TI_SCALE_OPERATOR_TOKEN_FILE: "/tmp/operator-token",
      TI_SCALE_SCRIPT_SOURCE_ROOT: "/tmp/ti-scale-script-sources",
      TMPDIR: "/tmp",
      TZ: "UTC",
    });
    expect(() => assertManagedE2EParentEnvironmentSafe({
      OPENROUTER_API_KEY: "live-provider-canary",
    })).toThrow("OPENROUTER_API_KEY");
    expect(() => assertManagedE2EParentEnvironmentSafe({
      TI_SCALE_OPERATOR_TOKEN: "inline-operator-canary",
    })).toThrow("TI_SCALE_OPERATOR_TOKEN");
    expect(() => assertManagedE2EParentEnvironmentSafe({
      OPENROUTER_API_KEY: " ",
    })).not.toThrow();
  });

  test("starts Playwright itself without inherited live credentials", () => {
    expect(playwrightChildEnvironment({
      PATH: "/reviewed/bin",
      HOME: "/tmp/e2e-home",
      CI: "true",
      TI_SCALE_E2E_PROFILE: "release",
      TI_SCALE_E2E_OPERATOR_TOKEN_FILE: "/tmp/operator-token",
      OPENROUTER_API_KEY: "must-not-reach-playwright",
      GITHUB_TOKEN: "must-not-reach-playwright",
      UNRELATED_CANARY_SECRET: "must-not-reach-playwright",
    })).toEqual({
      PATH: "/reviewed/bin",
      HOME: "/tmp/e2e-home",
      CI: "true",
      TI_SCALE_E2E_PROFILE: "release",
      TI_SCALE_E2E_OPERATOR_TOKEN_FILE: "/tmp/operator-token",
      TMPDIR: "/tmp",
      TZ: "UTC",
    });
  });

  test("keeps every managed database, auth, Vault, and credential path under the disposable root", () => {
    expect(assertManagedE2EFixturePath(
      `${E2E_DATA_ROOT}/isolated-fixture.sqlite`,
      "fixture",
    )).toBe(`${E2E_DATA_ROOT}/isolated-fixture.sqlite`);
    expect(() => assertManagedE2EFixturePath(
      "/etc/ti-scale/operator-token",
      "operator token",
    )).toThrow(`must be a child of ${E2E_DATA_ROOT}`);
    expect(() => assertManagedE2EFixturePath(
      E2E_DATA_ROOT,
      "database",
    )).toThrow(`must be a child of ${E2E_DATA_ROOT}`);
    expect(() => assertManagedE2EInvocationPaths()).not.toThrow();
  });
});
