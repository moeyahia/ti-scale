import {
  assertReleaseServiceStartAdmitted,
  RELEASE_SERVICE_START_AUTHORIZATION_SCHEMA,
} from "./ReleaseServiceStartAdmission";
import {
  assertReleaseServiceStartAdmissionInstallationCommitted,
} from "./ReleaseServiceStartAdmissionInstallation";
import { SHARED_RELEASE_LOCK_PATH } from "./ReleaseExecutionBoundary";

const TRANSACTION_ROOT = "/var/lib/ti-scale/release-transactions";
export const RELEASE_SERVICE_START_HELPER_PROTOCOL =
  "ti-scale.release-service-start-admission-helper.v1" as const;

export function releaseServiceStartAdmissionSelfReport(): Readonly<{
  schemaVersion: typeof RELEASE_SERVICE_START_HELPER_PROTOCOL;
  authorizationSchema: typeof RELEASE_SERVICE_START_AUTHORIZATION_SCHEMA;
}> {
  return Object.freeze({
    schemaVersion: RELEASE_SERVICE_START_HELPER_PROTOCOL,
    authorizationSchema: RELEASE_SERVICE_START_AUTHORIZATION_SCHEMA,
  });
}

export function runReleaseServiceStartAdmission(
  invocationId = process.env.INVOCATION_ID?.trim() ?? "",
): void {
  assertReleaseServiceStartAdmissionInstallationCommitted();
  const result = assertReleaseServiceStartAdmitted({
    transactionRoot: TRANSACTION_ROOT,
    releaseLockPath: SHARED_RELEASE_LOCK_PATH,
    invocationId,
  });
  process.stdout.write(result.mode === "ordinary"
    ? "Ti-Scale ordinary startup admitted: no nonterminal release transaction\n"
    : `Ti-Scale journal-owned startup admitted for ${result.transactionId ?? "unknown"}\n`);
}

if (import.meta.main) {
  try {
    if (process.argv.slice(2).includes("--self-report")) {
      process.stdout.write(`${JSON.stringify(releaseServiceStartAdmissionSelfReport())}\n`);
    } else {
      runReleaseServiceStartAdmission();
    }
  }
  catch (error) {
    process.stderr.write(
      `Ti-Scale startup admission denied: ${error instanceof Error ? error.message : "unknown admission error"}\n`,
    );
    process.exitCode = 1;
  }
}
