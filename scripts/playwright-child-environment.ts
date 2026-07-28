const PLAYWRIGHT_ENVIRONMENT_KEYS = new Set([
  "CI",
  "DBUS_SESSION_BUS_ADDRESS",
  "DISPLAY",
  "HOME",
  "LANG",
  "LC_ALL",
  "NO_COLOR",
  "PATH",
  "PLAYWRIGHT_BROWSERS_PATH",
  "PWDEBUG",
  "TERM",
  "TI_SCALE_BUN_EXECUTABLE",
  "TI_SCALE_E2E_API_URL",
  "TI_SCALE_E2E_AUTH_STATE",
  "TI_SCALE_E2E_BASE_URL",
  "TI_SCALE_E2E_CANDIDATE_SHA",
  "TI_SCALE_E2E_DATABASE_PATH",
  "TI_SCALE_E2E_DISCOVERY_ONLY",
  "TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS",
  "TI_SCALE_E2E_ENFORCE_MANIFEST",
  "TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY",
  "TI_SCALE_E2E_EXTERNAL_SERVERS",
  "TI_SCALE_E2E_OPERATOR_TOKEN_FILE",
  "TI_SCALE_E2E_PROFILE",
  "TI_SCALE_E2E_REQUIRE_API",
  "TI_SCALE_E2E_RUN_ID",
  "TI_SCALE_E2E_SERVER_MODE",
  "TI_SCALE_E2E_VAULT_ROOT",
  "TMPDIR",
  "TZ",
  "XDG_RUNTIME_DIR",
] as const);

export function playwrightChildEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const name of PLAYWRIGHT_ENVIRONMENT_KEYS) {
    const value = environment[name];
    if (value !== undefined) result[name] = value;
  }
  result.PATH ??= "/usr/local/bin:/usr/bin:/bin";
  result.HOME ??= "/tmp/ti-scale-e2e-home";
  result.TMPDIR ??= "/tmp";
  result.TZ ??= "UTC";
  return Object.freeze(result);
}
