export const AUTONOMOUS_DETERMINISTIC_FINDING_REFERENCE_SCHEMA_VERSION =
  "ti-scale.autonomous-deterministic-finding-reference.v1" as const;

export const AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID =
  "ti-scale.autonomous.cleartext-telnet-service.v1" as const;

export interface AutonomousDeterministicFindingPolicyReference {
  readonly schemaVersion: typeof AUTONOMOUS_DETERMINISTIC_FINDING_REFERENCE_SCHEMA_VERSION;
  readonly policyId: typeof AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID;
}

const TELNET_REFERENCE = Object.freeze({
  schemaVersion: AUTONOMOUS_DETERMINISTIC_FINDING_REFERENCE_SCHEMA_VERSION,
  policyId: AUTONOMOUS_CLEARTEXT_TELNET_FINDING_POLICY_ID,
}) satisfies AutonomousDeterministicFindingPolicyReference;

/**
 * The reviewed result verifier may stamp this reference only when its exact
 * normalized service fingerprints contain an open TCP Telnet service. The
 * terminal materializer independently revalidates the complete evidence,
 * observation, log-attribution, and custody boundary before creating a claim.
 */
export function deterministicFindingPolicyReferencesForServiceFingerprints(
  fingerprints: unknown,
): readonly AutonomousDeterministicFindingPolicyReference[] {
  if (!Array.isArray(fingerprints)) return Object.freeze([]);
  const telnetObserved = fingerprints.some((fingerprint) => {
    if (fingerprint === null || typeof fingerprint !== "object" || Array.isArray(fingerprint)) {
      return false;
    }
    const value = fingerprint as Readonly<Record<string, unknown>>;
    return value.transport === "tcp"
      && value.state === "open"
      && typeof value.port === "number"
      && Number.isSafeInteger(value.port)
      && value.port >= 1
      && value.port <= 65_535
      && typeof value.service === "string"
      && value.service.toLocaleLowerCase("en-US") === "telnet";
  });
  return telnetObserved ? Object.freeze([TELNET_REFERENCE]) : Object.freeze([]);
}
