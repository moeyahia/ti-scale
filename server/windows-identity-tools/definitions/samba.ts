import type { WindowsIdentityToolDefinition } from "../types";
import { identityExecution, identityProbe } from "./shared";

export const SMBCLIENT_SHARE_LIST_DEFINITION: WindowsIdentityToolDefinition = Object.freeze({
  toolId: "kali:smbclient-share-list",
  operation: "smb_share_list",
  label: "SMB share list",
  executable: Object.freeze({
    path: "/usr/bin/smbclient",
    sha256: "a72e60c20271a9a90f723d53e604edb7c96d9562367f3c9711e02cea116991bd",
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
