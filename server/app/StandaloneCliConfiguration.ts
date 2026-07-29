import { isAbsolute, resolve } from "node:path";

export type TiScaleCliEnvironment = Readonly<Record<string, string | undefined>>;

function explicitOrEnvironment(
  explicit: string | undefined,
  environmentValue: string | undefined,
  argumentName: string,
  environmentName: "TI_SCALE_DATABASE_PATH" | "TI_SCALE_VAULT_ROOT",
): string {
  if (explicit !== undefined) {
    const normalized = explicit.trim();
    if (!normalized) throw new Error(`--${argumentName} must not be empty`);
    return normalized;
  }
  const normalized = environmentValue?.trim();
  if (!normalized) throw new Error(`--${argumentName} or ${environmentName} is required`);
  return normalized;
}

/** Resolve the one canonical database setting shared by standalone maintenance CLIs. */
export function resolveCliDatabasePath(
  explicit: string | undefined,
  environment: TiScaleCliEnvironment = process.env,
): string {
  return resolve(explicitOrEnvironment(
    explicit,
    environment.TI_SCALE_DATABASE_PATH,
    "db",
    "TI_SCALE_DATABASE_PATH",
  ));
}

/** Resolve the filesystem sandbox root without weakening its absolute-path contract. */
export function resolveCliVaultRoot(
  explicit: string | undefined,
  environment: TiScaleCliEnvironment = process.env,
): string {
  const configured = explicitOrEnvironment(
    explicit,
    environment.TI_SCALE_VAULT_ROOT,
    "vault-root",
    "TI_SCALE_VAULT_ROOT",
  );
  if (!isAbsolute(configured)) {
    throw new Error("--vault-root or TI_SCALE_VAULT_ROOT must be an absolute path");
  }
  return resolve(configured);
}
