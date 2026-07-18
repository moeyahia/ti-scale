export type CveApplicability =
  | "confirmed"
  | "likely"
  | "possible"
  | "not_applicable"
  | "insufficient_evidence";

export type CveSourceKind = "cve_org" | "nvd" | "mitre" | "cisa" | "vendor";
export type KevStatus = "listed" | "not_listed" | "unknown";

export type CveIntelligenceJson =
  | string
  | number
  | boolean
  | null
  | readonly CveIntelligenceJson[]
  | { readonly [key: string]: CveIntelligenceJson };

export interface CveSourceLink {
  readonly kind: CveSourceKind;
  readonly url: string;
  readonly label: string;
}

export interface CveApplicabilityRecord {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly assetNodeId?: string;
  readonly serviceNodeId?: string;
  readonly cveId: string;
  readonly title: string;
  readonly description: string;
  readonly component: string;
  readonly detectedVersion?: string;
  readonly affectedRange?: string;
  readonly cpeOrPackage: Readonly<Record<string, CveIntelligenceJson>>;
  readonly applicability: CveApplicability;
  readonly confidence: number;
  readonly reasoningSummary: string;
  readonly cvss: Readonly<Record<string, CveIntelligenceJson>>;
  readonly cwe: readonly string[];
  readonly epss?: number;
  readonly kevStatus?: KevStatus;
  readonly exploitMaturity?: string;
  readonly publishedAt?: string;
  readonly modifiedAt?: string;
  readonly sourceLinks: readonly CveSourceLink[];
  readonly sourceRetrievedAt: string;
  readonly sourceVersion?: string;
  readonly discoveryAgentId?: string;
  readonly versionEvidenceId?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CveApplicabilityList {
  readonly schemaVersion: "2.4";
  readonly items: readonly CveApplicabilityRecord[];
}

export interface CveApplicabilityDetail {
  readonly schemaVersion: "2.4";
  readonly record: CveApplicabilityRecord;
}

export interface CveApplicabilityFilter {
  readonly runId?: string;
  readonly assetNodeId?: string;
  readonly serviceNodeId?: string;
  readonly applicability?: CveApplicability;
  readonly limit?: number;
}
