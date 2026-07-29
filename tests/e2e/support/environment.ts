import { randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";
import { resolveOperatorToken } from "../../../server/auth/OperatorTokenConfiguration";

export const E2E_RUN_ID = process.env.TI_SCALE_E2E_RUN_ID
  ?? `${process.pid}-${Date.now()}`;
export const E2E_DATA_ROOT = resolve("/tmp/ti-scale-e2e-data");

// Playwright config, web servers, global setup, and worker processes inherit
// this exact path. A unique database per invocation prevents previous real
// E2E missions from changing control counts or fixture outcomes.
process.env.TI_SCALE_E2E_RUN_ID ??= E2E_RUN_ID;
process.env.TI_SCALE_E2E_DATABASE_PATH ??= resolve(
  E2E_DATA_ROOT,
  `ti-scale-${E2E_RUN_ID}.sqlite`,
);
const generatedOperatorTokenFile = resolve(
  E2E_DATA_ROOT,
  `operator-token-${E2E_RUN_ID}`,
);
const generatedResearchIntegrityKeyFile = resolve(
  E2E_DATA_ROOT,
  `research-integrity-key-${E2E_RUN_ID}`,
);
export const E2E_PROVIDER_CONFIG_ROOT = resolve(
  E2E_DATA_ROOT,
  `provider-config-${E2E_RUN_ID}`,
);
export const E2E_SCRIPT_SOURCE_ROOT = resolve(
  E2E_DATA_ROOT,
  `ti-scale-script-sources-${E2E_RUN_ID}`,
);

const configuredOperatorTokenFile = process.env.TI_SCALE_E2E_OPERATOR_TOKEN_FILE?.trim();
const isolatedOperatorTokenFile = configuredOperatorTokenFile
  ? assertManagedE2EFixturePath(
    configuredOperatorTokenFile,
    "The configured E2E operator-token file",
  )
  : undefined;
if (
  isolatedOperatorTokenFile
  && isolatedOperatorTokenFile !== generatedOperatorTokenFile
) {
  throw new Error(
    "The configured E2E operator-token file must use this invocation's exact generated path",
  );
}
const inlineOperatorToken = process.env.TI_SCALE_E2E_OPERATOR_TOKEN
  ?? "ti-scale-e2e-local-operator-token-2026";

const resolvedOperatorToken = resolveOperatorToken(isolatedOperatorTokenFile
  ? { TI_SCALE_OPERATOR_TOKEN_FILE: isolatedOperatorTokenFile }
  : { TI_SCALE_OPERATOR_TOKEN: inlineOperatorToken });
if (!resolvedOperatorToken) throw new Error("The E2E operator credential is not configured");
export const E2E_OPERATOR_TOKEN: string = resolvedOperatorToken;
export const E2E_RESEARCH_INTEGRITY_HMAC_KEY =
  "ti-scale-e2e-local-research-integrity-key-material-2026";

function writePrivateFixtureFile(path: string, value: string): string {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const directoryMetadata = lstatSync(directory);
  if (!directoryMetadata.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw new Error("The E2E private credential directory must be a real directory");
  }
  chmodSync(directory, 0o700);

  const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporaryPath, `${value}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    chmodSync(temporaryPath, 0o600);
    renameSync(temporaryPath, path);
    chmodSync(path, 0o600);
  } finally {
    if (existsSync(temporaryPath)) unlinkSync(temporaryPath);
  }
  return path;
}

export function assertManagedE2EFixturePath(path: string, label: string): string {
  const resolved = resolve(path);
  const inside = relative(E2E_DATA_ROOT, resolved);
  if (
    inside === ""
    || inside === ".."
    || inside.startsWith(`..${sep}`)
    || isAbsolute(inside)
  ) {
    throw new Error(`${label} must be a child of ${E2E_DATA_ROOT}`);
  }

  if (existsSync(E2E_DATA_ROOT)) {
    const rootMetadata = lstatSync(E2E_DATA_ROOT);
    if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
      throw new Error("The managed E2E data root must be a real directory");
    }
  }
  const segments = inside.split(sep);
  let current = E2E_DATA_ROOT;
  for (const segment of segments.slice(0, -1)) {
    current = resolve(current, segment);
    if (!existsSync(current)) break;
    const metadata = lstatSync(current);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error(`${label} traverses a non-directory or symbolic-link parent`);
    }
  }
  if (existsSync(resolved) && lstatSync(resolved).isSymbolicLink()) {
    throw new Error(`${label} must not be a symbolic link`);
  }
  return resolved;
}

/**
 * Materialize an inline disposable E2E credential as a private file before a
 * Playwright-managed server starts. A caller-supplied fixture may be reused
 * only at this invocation's exact private path. The returned path is safe to
 * serialize in test reports; the credential value is not.
 */
export function prepareManagedE2EOperatorTokenFile(): string {
  if (isolatedOperatorTokenFile) return isolatedOperatorTokenFile;
  return writePrivateFixtureFile(
    generatedOperatorTokenFile,
    E2E_OPERATOR_TOKEN,
  );
}

/**
 * Give the managed server only a private key-file path. The key value remains
 * available to local fixture builders but never appears in Playwright's
 * serializable webServer configuration or reporters.
 */
export function prepareManagedE2EResearchIntegrityKeyFile(): string {
  return writePrivateFixtureFile(
    generatedResearchIntegrityKeyFile,
    E2E_RESEARCH_INTEGRITY_HMAC_KEY,
  );
}
export const E2E_API_URL = process.env.TI_SCALE_E2E_API_URL ?? "http://127.0.0.1:43141";
export const E2E_AUTH_STATE = process.env.TI_SCALE_E2E_AUTH_STATE
  ?? resolve(
    E2E_DATA_ROOT,
    `auth-state-${E2E_RUN_ID}.json`,
  );
export const E2E_DATABASE_PATH = process.env.TI_SCALE_E2E_DATABASE_PATH;
export const E2E_VAULT_ROOT = process.env.TI_SCALE_E2E_VAULT_ROOT ?? resolve(
  E2E_DATA_ROOT,
  `vaults-${E2E_RUN_ID}`,
);

export function assertManagedE2EInvocationPaths(): void {
  const exactPaths = [
    [
      E2E_DATABASE_PATH,
      resolve(E2E_DATA_ROOT, `ti-scale-${E2E_RUN_ID}.sqlite`),
      "database",
    ],
    [
      E2E_AUTH_STATE,
      resolve(E2E_DATA_ROOT, `auth-state-${E2E_RUN_ID}.json`),
      "authentication state",
    ],
    [
      E2E_VAULT_ROOT,
      resolve(E2E_DATA_ROOT, `vaults-${E2E_RUN_ID}`),
      "Vault root",
    ],
    [
      E2E_PROVIDER_CONFIG_ROOT,
      resolve(E2E_DATA_ROOT, `provider-config-${E2E_RUN_ID}`),
      "provider-configuration root",
    ],
    [
      E2E_SCRIPT_SOURCE_ROOT,
      resolve(E2E_DATA_ROOT, `ti-scale-script-sources-${E2E_RUN_ID}`),
      "script-source root",
    ],
  ] as const;
  for (const [actual, expected, label] of exactPaths) {
    if (!actual || resolve(actual) !== expected) {
      throw new Error(
        `The managed E2E ${label} must use this invocation's exact path ${expected}`,
      );
    }
    assertManagedE2EFixturePath(actual, `The managed E2E ${label}`);
  }
}

export function disposeManagedE2EInvocation(): void {
  assertManagedE2EInvocationPaths();
  const paths = [
    generatedOperatorTokenFile,
    generatedResearchIntegrityKeyFile,
    E2E_AUTH_STATE,
    E2E_DATABASE_PATH!,
    `${E2E_DATABASE_PATH!}-shm`,
    `${E2E_DATABASE_PATH!}-wal`,
    `${E2E_DATABASE_PATH!}.operational-hazard-hmac`,
    E2E_VAULT_ROOT,
    E2E_PROVIDER_CONFIG_ROOT,
    E2E_SCRIPT_SOURCE_ROOT,
  ];
  for (const path of paths) {
    assertManagedE2EFixturePath(path, "Managed E2E cleanup path");
    rmSync(path, { force: true, recursive: true });
  }
}
