import type { WindowsIdentityOperation } from "./types";

export interface WindowsIdentityOperationPresentation {
  readonly title: string;
  readonly description: string;
  objective(target: string): string;
  readonly expectedResult: string;
}

/**
 * Product copy for the reviewed Windows/identity operations. Both mission
 * intake and the runtime planner consume this registry so the represented
 * action cannot drift into a second UI-only description.
 */
export const WINDOWS_IDENTITY_OPERATION_PRESENTATION: Readonly<
Record<WindowsIdentityOperation, WindowsIdentityOperationPresentation>
> = Object.freeze({
  smb_share_list: {
    title: "List the SMB shares the approved host exposes",
    objective: (target) => `Ask ${target} for its advertised SMB share names and types.`,
    description: "Ti-Scale makes one read-only SMB listing request to the exact approved host. Anonymous mode sends no credential; credential mode uses only the selected opaque private reference. It does not open files, write to a share, try passwords, or contact another host.",
    expectedResult: "A bounded list of advertised shares, an access-denied response, or a precise connection, policy, dependency, or timeout failure.",
  },
  smb_identity_summary: {
    title: "Read the approved host’s SMB identity summary",
    objective: (target) => `Confirm the SMB host, domain, signing, and protocol details reported by ${target}.`,
    description: "Ti-Scale makes one bounded SMB metadata and share check against the exact approved host. It can try an anonymous read with no credential, or use one operator-selected opaque credential reference whose files stay private to the sandbox. It does not spray passwords, test local-admin access, write to shares, or execute commands.",
    expectedResult: "Attributable host and domain metadata with SMB security settings, or a precise authentication, connection, policy, dependency, or timeout failure.",
  },
  ldap_root_dse: {
    title: "Read the LDAP directory’s public root metadata",
    objective: (target) => `Ask ${target} for the small public metadata record that identifies its LDAP directory namespaces and supported protocols.`,
    description: "Ti-Scale makes one anonymous, read-only LDAP base query to the exact approved host. It asks only for a fixed set of root-directory metadata and does not enumerate users, groups, computers, or neighboring systems.",
    expectedResult: "Directory namespace and protocol metadata, an access-denied response, or a precise connection, policy, dependency, or timeout failure.",
  },
  rpc_domain_info: {
    title: "Read the approved host’s RPC domain summary",
    objective: (target) => `Ask ${target} for its bounded Windows domain summary over RPC.`,
    description: "Ti-Scale makes one read-only RPC domain-information request to the exact approved host. Anonymous mode sends no credential; credential mode uses only the selected opaque private reference. It does not enumerate accounts, change domain objects, or execute commands.",
    expectedResult: "A bounded domain-role and object-count summary, an access-denied response, or a precise connection, policy, dependency, or timeout failure.",
  },
});
