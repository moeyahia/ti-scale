import { createHash } from "node:crypto";

/**
 * Stable identities keep one run's observations idempotent without merging
 * time-specific reconnaissance from different runs. Asset and service values
 * intentionally preserve the identity scheme first used by the reviewed Nmap
 * materializer.
 */
export function runScopedTopologyIdentity(
  runId: string,
  kind:
    | "asset"
    | "service"
    | "domain"
    | "web_origin"
    | "endpoint"
    | "technology_signal"
    | "page_capture_artifact",
  value: string,
): string {
  const digest = createHash("sha256")
    .update(runId, "utf8")
    .update("\0", "utf8")
    .update(kind, "utf8")
    .update("\0", "utf8")
    .update(value.normalize("NFKC").toLocaleLowerCase("en-US"), "utf8")
    .digest("hex");
  return `${kind}:run-scoped:${digest}`;
}
