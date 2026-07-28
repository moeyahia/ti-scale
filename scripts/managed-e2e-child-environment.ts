const CHILD_ENVIRONMENT_KEYS = new Set([
  "CHOKIDAR_INTERVAL",
  "CHOKIDAR_USEPOLLING",
  "CI",
  "HOME",
  "LANG",
  "LC_ALL",
  "NO_COLOR",
  "PATH",
  "TERM",
  "TI_SCALE_API_ORIGIN",
  "TI_SCALE_DATABASE_PATH",
  "TI_SCALE_DIST_ROOT",
  "TI_SCALE_E2E_RUN_ID",
  "TI_SCALE_E2E_STATIC_BUILD_ID",
  "TI_SCALE_HOST",
  "TI_SCALE_OPERATOR_ID",
  "TI_SCALE_OPERATOR_TOKEN_FILE",
  "TI_SCALE_PERFORMANCE_BUILD",
  "TI_SCALE_PORT",
  "TI_SCALE_PREVIEW",
  "TI_SCALE_PROVIDER_CONFIG_ROOT",
  "TI_SCALE_PROJECTION_INTERVAL_MS",
  "TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY_FILE",
  "TI_SCALE_SCRIPT_SOURCE_ROOT",
  "TI_SCALE_SERVE_STATIC",
  "TI_SCALE_TEST_RUN_CONTROL_RUNTIME",
  "TI_SCALE_TEST_RUN_CONTROL_SCHEDULER",
  "TI_SCALE_UI_ORIGIN",
  "TI_SCALE_VAULT_ROOT",
  "TMPDIR",
  "TZ",
] as const);

const FORBIDDEN_PARENT_CREDENTIAL_NAMES = Object.freeze([
  "ANTHROPIC_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_API_KEY",
  "GROK_API_KEY",
  "MESHY_API_KEY",
  "OPENAI_API_KEY",
  "OPENROUTER_API_KEY",
  "XAI_API_KEY",
  "TI_SCALE_OPERATOR_TOKEN",
  "TI_SCALE_RESEARCH_INTEGRITY_HMAC_KEY",
] as const);

export function assertManagedE2EParentEnvironmentSafe(
  environment: Readonly<Record<string, string | undefined>>,
): void {
  const exposed = FORBIDDEN_PARENT_CREDENTIAL_NAMES.filter((name) =>
    Boolean(environment[name]?.trim()));
  if (exposed.length > 0) {
    throw new Error(
      "Managed browser tests refuse inherited live credentials: "
        + exposed.join(", "),
    );
  }
}

export function managedE2EChildEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const name of CHILD_ENVIRONMENT_KEYS) {
    const value = environment[name];
    if (value !== undefined) result[name] = value;
  }
  result.PATH ??= "/usr/local/bin:/usr/bin:/bin";
  result.HOME ??= "/tmp/ti-scale-e2e-home";
  result.TMPDIR ??= "/tmp";
  result.TZ ??= "UTC";
  return Object.freeze(result);
}
