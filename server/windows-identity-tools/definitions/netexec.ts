import type { WindowsIdentityToolDefinition } from "../types";
import { identityExecution, identityProbe } from "./shared";

export const NXC_SMB_SUMMARY_DEFINITION: WindowsIdentityToolDefinition = Object.freeze({
  toolId: "kali:nxc-smb-summary",
  operation: "smb_identity_summary",
  label: "SMB identity summary",
  executable: Object.freeze({
    path: "/usr/bin/nxc",
    sha256: "052fd76ba684d5dafc8216f456f1b5b9e9cebf7291aeb90f195852597bffd4cd",
    ownerUid: 0,
    fileCapabilities: "none",
  }),
  // NetExec prints its version successfully but intentionally exits 1.
  probe: identityProbe(["--version"], [0, 1]),
  actionClassId: "active_directory_identity_operations",
  evidenceTypeId: "identity_ad_graph",
  journeyPolicy: "guided_only",
  authenticationModes: Object.freeze(["credential_reference"] as const),
  execution: identityExecution(20_000, 768 * 1_024),
});
