import type { WindowsIdentityToolDefinition } from "../types";
import { identityExecution, identityProbe } from "./shared";

export const RPCCLIENT_DOMAIN_INFO_DEFINITION: WindowsIdentityToolDefinition = Object.freeze({
  toolId: "kali:rpcclient-domain-info",
  operation: "rpc_domain_info",
  label: "RPC domain information",
  executable: Object.freeze({
    path: "/usr/bin/rpcclient",
    sha256: "806a2470ea3579efefd1e0864efdcab980263fe7ff13a768c84354bbbc062010",
    ownerUid: 0,
    fileCapabilities: "none",
  }),
  probe: identityProbe(["--version"]),
  actionClassId: "active_directory_identity_operations",
  evidenceTypeId: "identity_ad_graph",
  journeyPolicy: "guided_only",
  authenticationModes: Object.freeze(["anonymous", "credential_reference"] as const),
  execution: identityExecution(15_000, 512 * 1_024),
});
