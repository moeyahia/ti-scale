import type { OperationalSensitivity } from "./operationalTruth";

export type PageCaptureRedactionState = "not_required" | "pending" | "redacted" | "quarantined";

export interface PageCaptureArtifactProjection {
  readonly artifactId: string;
  readonly contentHash: string;
  readonly mediaType: string;
  readonly byteSize: number;
}

export interface PageCaptureRecord {
  readonly id: string;
  readonly missionId: string;
  readonly runId?: string;
  readonly planId?: string;
  readonly stepId?: string;
  readonly stepTitle?: string;
  readonly assetNodeId?: string;
  readonly assetLabel?: string;
  readonly serviceNodeId?: string;
  readonly serviceLabel?: string;
  readonly normalizedUrl: string;
  readonly responseStatus?: number;
  readonly title?: string;
  readonly viewport: {
    readonly width: number;
    readonly height: number;
    readonly deviceScaleFactor: number;
    readonly isMobile: boolean;
    readonly fullPage: boolean;
  };
  readonly screenshot?: PageCaptureArtifactProjection;
  readonly fullPageScreenshot?: PageCaptureArtifactProjection;
  readonly contentHash: string;
  readonly screenshotHash?: string;
  readonly fullPageScreenshotHash?: string;
  readonly certificate: {
    readonly protocol?: string;
    readonly cipher?: string;
    readonly subjectCommonName?: string;
    readonly issuerCommonName?: string;
    readonly sanDnsNames?: readonly string[];
    readonly validFrom?: string;
    readonly validTo?: string;
    readonly fingerprintSha256?: string;
    readonly verified?: boolean;
  };
  readonly site: {
    readonly contentType?: string;
    readonly contentLength?: number;
    readonly language?: string;
    readonly contentEncoding?: string;
    readonly serverProduct?: string;
    readonly technologies?: readonly string[];
    readonly securityHeaders?: readonly { readonly name: string; readonly value: string }[];
  };
  readonly related: {
    readonly evidenceIds: readonly string[];
    readonly observationIds: readonly string[];
    readonly findingIds: readonly string[];
  };
  readonly capturedByAgentId?: string;
  readonly capturedByAgentName?: string;
  readonly captureTool: string;
  readonly sensitivity: OperationalSensitivity;
  readonly redactionState: PageCaptureRedactionState;
  readonly capturedAt: string;
  readonly createdAt: string;
  readonly gallery: {
    readonly label: string;
    readonly previewArtifactId: string | null;
    readonly fullPageArtifactId: string | null;
    readonly previewAvailable: boolean;
    readonly redactionState: PageCaptureRedactionState;
  };
}

export interface PageCaptureList {
  readonly schemaVersion: "2.4";
  readonly items: readonly PageCaptureRecord[];
  readonly nextCursor?: string;
}

export interface PageCaptureDetail {
  readonly schemaVersion: "2.4";
  readonly record: PageCaptureRecord;
}

export interface PageCaptureFilter {
  readonly runId?: string;
  readonly assetNodeId?: string;
  readonly serviceNodeId?: string;
  readonly redactionState?: PageCaptureRedactionState;
  readonly cursor?: string;
  readonly limit?: number;
}
