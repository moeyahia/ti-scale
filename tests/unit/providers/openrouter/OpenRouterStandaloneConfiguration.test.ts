import { describe, expect, test } from "bun:test";
import {
  resolveOpenRouterGuidedStandaloneConfiguration,
} from "../../../../server/providers/openrouter";

describe("OpenRouter standalone Guided configuration", () => {
  test("does not accept or copy a raw environment credential", () => {
    const secret = "sk-or-v1-this-must-never-enter-configuration";
    const configuration = resolveOpenRouterGuidedStandaloneConfiguration({
      OPENROUTER_API_KEY: secret,
    });
    expect(configuration).toMatchObject({
      state: "blocked",
      reasonCode: "raw_environment_credential_unsupported",
    });
    expect(JSON.stringify(configuration)).not.toContain(secret);
  });

  test("distinguishes disabled, invalid, and incomplete configuration deterministically", () => {
    expect(resolveOpenRouterGuidedStandaloneConfiguration({})).toMatchObject({
      state: "disabled",
      reasonCode: "not_configured",
    });
    expect(resolveOpenRouterGuidedStandaloneConfiguration({
      TI_SCALE_OPENROUTER_GUIDED_ENABLED: "false",
      OPENROUTER_API_KEY: "ignored-while-explicitly-disabled",
    })).toMatchObject({
      state: "disabled",
      reasonCode: "explicitly_disabled",
    });
    expect(resolveOpenRouterGuidedStandaloneConfiguration({
      TI_SCALE_OPENROUTER_GUIDED_ENABLED: "yes",
    })).toMatchObject({
      state: "blocked",
      reasonCode: "enabled_flag_invalid",
    });
    expect(resolveOpenRouterGuidedStandaloneConfiguration({
      TI_SCALE_OPENROUTER_GUIDED_ENABLED: "true",
    })).toMatchObject({
      state: "blocked",
      reasonCode: "credential_path_missing",
    });
    expect(resolveOpenRouterGuidedStandaloneConfiguration({
      TI_SCALE_OPENROUTER_CREDENTIAL_PATH: "relative/key",
    })).toMatchObject({
      state: "blocked",
      reasonCode: "credential_path_not_absolute",
    });
  });

  test("pins an absolute file configuration but keeps it explicitly unattested", () => {
    const configuration = resolveOpenRouterGuidedStandaloneConfiguration({
      TI_SCALE_OPENROUTER_GUIDED_ENABLED: "true",
      TI_SCALE_OPENROUTER_CREDENTIAL_PATH: "/run/credentials/ti-scale/openrouter",
      TI_SCALE_OPENROUTER_MODEL: "openai/gpt-5.4-mini",
    });
    expect(configuration).toMatchObject({
      state: "configured_unattested",
      credentialPath: "/run/credentials/ti-scale/openrouter",
      modelConfiguration: {
        providerId: "openrouter",
        model: "openai/gpt-5.4-mini",
        configurationHash: expect.stringMatching(/^[a-f0-9]{64}$/u),
      },
      reason: expect.stringContaining("no fresh audited"),
    });
    if (configuration.state === "configured_unattested") {
      expect(configuration.modelConfiguration.endpoint)
        .toBe("https://openrouter.ai/api/v1/chat/completions");
    }
  });
});
