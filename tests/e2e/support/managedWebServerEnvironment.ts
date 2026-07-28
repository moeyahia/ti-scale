const MANAGED_WEB_SERVER_KEYS = new Set([
  "TI_SCALE_API_ORIGIN",
  "TI_SCALE_DATABASE_PATH",
  "TI_SCALE_DIST_ROOT",
  "TI_SCALE_E2E_RUN_ID",
  "TI_SCALE_E2E_STATIC_BUILD_ID",
  "TI_SCALE_E2E_UI_HOST",
  "TI_SCALE_E2E_UI_PORT",
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
] as const);

/**
 * Playwright already merges the parent process environment when it launches a
 * managed web server. Repeating `process.env` inside `webServer.env` is both
 * unnecessary and unsafe: Playwright exposes that configuration to reporters.
 *
 * Keep only the explicit, non-secret test overrides in reportable config. The
 * operator credential is represented by a private file path, never by its
 * value. Unknown keys fail closed so a future `...process.env` spread cannot
 * silently reintroduce inherited credentials.
 */
export function managedWebServerEnvironment(
  values: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string>> {
  const environment: Record<string, string> = {};
  for (const [name, value] of Object.entries(values)) {
    if (value === undefined) continue;
    if (!MANAGED_WEB_SERVER_KEYS.has(name as (typeof MANAGED_WEB_SERVER_KEYS extends Set<infer T> ? T : never))) {
      throw new Error(`Managed Playwright web-server environment key is not report-safe: ${name}`);
    }
    if (name === "TI_SCALE_OPERATOR_TOKEN") {
      throw new Error("Managed Playwright web servers must receive the operator credential through a private file");
    }
    environment[name] = value;
  }
  return Object.freeze(environment);
}
