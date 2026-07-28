export type E2EProfileName = "development" | "release" | "degraded";

export const PLAYWRIGHT_MANAGED_STATIC_SERVER_MODE = "playwright-managed-static" as const;

const DEFAULT_BASE_URL = "http://127.0.0.1:43140";
const DEFAULT_API_URL = "http://127.0.0.1:43141";

export interface LocalReleaseAttestation {
  readonly immutableSourceAttested: false;
  readonly releaseCandidateEligible: false;
  readonly blockers: readonly string[];
}

export const LOCAL_RELEASE_ATTESTATION: LocalReleaseAttestation = Object.freeze({
  immutableSourceAttested: false,
  releaseCandidateEligible: false,
  blockers: Object.freeze([
    "The exact source revision and working tree have not been independently attested.",
    "The managed production server and built distribution have not been cryptographically attested.",
    "A local release-profile run cannot substitute for the required soak, preview acceptance, rollback rehearsal, and human sign-off.",
  ]),
});

export interface ParsedE2EProfile {
  readonly profile: E2EProfileName;
  readonly requireApi: boolean;
  readonly enforceManifest: boolean;
  readonly serverMode: string | undefined;
  readonly externalServers: boolean;
  readonly baseURL: string;
  readonly apiURL: string;
  readonly releaseAttestation: LocalReleaseAttestation | undefined;
}

type E2EEnvironment = Readonly<Record<string, string | undefined>>;

function configuredValue(environment: E2EEnvironment, name: string): string | undefined {
  const value = environment[name]?.trim();
  return value ? value : undefined;
}

function parsedUrl(value: string, variableName: string, violations: string[]): URL | undefined {
  try {
    return new URL(value);
  } catch {
    violations.push(`${variableName} must be an absolute URL; received ${JSON.stringify(value)}`);
    return undefined;
  }
}

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === "localhost" || normalized === "[::1]" || normalized === "::1") return true;

  const octets = normalized.split(".");
  if (octets.length !== 4 || octets[0] !== "127") return false;
  return octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255);
}

function validateReleaseUrl(
  url: URL | undefined,
  variableName: string,
  violations: string[],
): void {
  if (!url) return;
  if (url.protocol !== "http:") {
    violations.push(`${variableName} must use local HTTP for the managed release server; received ${url.protocol}`);
  }
  if (!isLoopbackHost(url.hostname)) {
    violations.push(`${variableName} must use a loopback host; received ${url.hostname}`);
  }
  if (url.username || url.password) {
    violations.push(`${variableName} must not contain URL credentials`);
  }
}

function validateExactReleaseValue(
  environment: E2EEnvironment,
  name: string,
  expected: string,
  violations: string[],
): void {
  const actual = environment[name];
  if (actual !== expected) {
    violations.push(`${name} must equal ${JSON.stringify(expected)}; received ${JSON.stringify(actual)}`);
  }
}

function validateReleaseContract(
  environment: E2EEnvironment,
  baseURL: string,
  apiURL: string,
): void {
  const violations: string[] = [];
  validateExactReleaseValue(environment, "TI_SCALE_E2E_REQUIRE_API", "1", violations);
  validateExactReleaseValue(environment, "TI_SCALE_E2E_ENFORCE_MANIFEST", "1", violations);
  validateExactReleaseValue(
    environment,
    "TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS",
    "1",
    violations,
  );
  validateExactReleaseValue(
    environment,
    "TI_SCALE_E2E_ENFORCE_RELEASE_RESULT_POLICY",
    "1",
    violations,
  );
  validateExactReleaseValue(
    environment,
    "TI_SCALE_E2E_SERVER_MODE",
    PLAYWRIGHT_MANAGED_STATIC_SERVER_MODE,
    violations,
  );
  validateExactReleaseValue(environment, "TI_SCALE_E2E_EXTERNAL_SERVERS", "false", violations);
  if (!/^[a-f0-9]{40}$/u.test(environment.TI_SCALE_E2E_CANDIDATE_SHA ?? "")) {
    violations.push(
      "TI_SCALE_E2E_CANDIDATE_SHA must be the exact lowercase 40-character checked-out Git commit",
    );
  }

  if (!configuredValue(environment, "TI_SCALE_E2E_BASE_URL")) {
    violations.push("TI_SCALE_E2E_BASE_URL must be explicitly set for the release profile");
  }
  if (!configuredValue(environment, "TI_SCALE_E2E_API_URL")) {
    violations.push("TI_SCALE_E2E_API_URL must be explicitly set for the release profile");
  }

  const parsedBaseURL = parsedUrl(baseURL, "TI_SCALE_E2E_BASE_URL", violations);
  const parsedApiURL = parsedUrl(apiURL, "TI_SCALE_E2E_API_URL", violations);
  validateReleaseUrl(parsedBaseURL, "TI_SCALE_E2E_BASE_URL", violations);
  validateReleaseUrl(parsedApiURL, "TI_SCALE_E2E_API_URL", violations);
  if (parsedBaseURL && parsedApiURL && parsedBaseURL.origin !== parsedApiURL.origin) {
    violations.push(
      `TI_SCALE_E2E_BASE_URL and TI_SCALE_E2E_API_URL must have the same origin; received ${parsedBaseURL.origin} and ${parsedApiURL.origin}`,
    );
  }

  if (violations.length > 0) {
    throw new Error(`Release E2E profile contract failed:\n- ${violations.join("\n- ")}`);
  }
}

export function parseE2EProfile(environment: E2EEnvironment = process.env): ParsedE2EProfile {
  const profile = configuredValue(environment, "TI_SCALE_E2E_PROFILE") ?? "development";
  if (profile !== "development" && profile !== "release" && profile !== "degraded") {
    throw new Error(
      `TI_SCALE_E2E_PROFILE must be development, release, or degraded; received ${profile}`,
    );
  }

  if (profile !== "degraded" && environment.TI_SCALE_E2E_REQUIRE_API === "0") {
    throw new Error("Required V2 API auditing can be relaxed only by the explicit degraded profile");
  }

  const baseURL = configuredValue(environment, "TI_SCALE_E2E_BASE_URL") ?? DEFAULT_BASE_URL;
  const apiURL = configuredValue(environment, "TI_SCALE_E2E_API_URL") ?? DEFAULT_API_URL;
  if (profile === "release") validateReleaseContract(environment, baseURL, apiURL);

  return Object.freeze({
    profile,
    requireApi: profile !== "degraded",
    enforceManifest: profile === "release" || configuredValue(environment, "TI_SCALE_E2E_ENFORCE_MANIFEST") === "1",
    serverMode: configuredValue(environment, "TI_SCALE_E2E_SERVER_MODE"),
    externalServers: configuredValue(environment, "TI_SCALE_E2E_EXTERNAL_SERVERS") === "true",
    baseURL,
    apiURL,
    releaseAttestation: profile === "release" ? LOCAL_RELEASE_ATTESTATION : undefined,
  });
}
