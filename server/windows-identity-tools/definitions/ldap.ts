import type { WindowsIdentityToolDefinition } from "../types";
import { identityExecution, identityProbe } from "./shared";

export const LDAPSEARCH_ROOT_DSE_DEFINITION: WindowsIdentityToolDefinition = Object.freeze({
  toolId: "kali:ldapsearch-root-dse",
  operation: "ldap_root_dse",
  label: "LDAP directory identity",
  executable: Object.freeze({
    path: "/usr/bin/ldapsearch",
    sha256: "88216b0e078e36007ecc64ede6c574380018932a9fdd90c3abfba6a7f9ad68b8",
    ownerUid: 0,
    fileCapabilities: "none",
  }),
  probe: identityProbe(["-VV"]),
  actionClassId: "active_directory_identity_operations",
  evidenceTypeId: "identity_ad_graph",
  journeyPolicy: "guided_only",
  authenticationModes: Object.freeze(["anonymous"] as const),
  execution: identityExecution(12_000, 384 * 1_024),
});
