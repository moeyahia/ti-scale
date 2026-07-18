import type { Sensitivity } from "../intelligence-v24/types";

export type PageCaptureRedactionState =
  | "not_required"
  | "pending"
  | "redacted"
  | "quarantined";

export interface PageCaptureViewport {
  readonly width: number;
  readonly height: number;
  readonly deviceScaleFactor: number;
  readonly isMobile: boolean;
  readonly fullPage: boolean;
}

export interface PageCaptureCertificateMetadata {
  readonly protocol?: string;
  readonly cipher?: string;
  readonly subjectCommonName?: string;
  readonly issuerCommonName?: string;
  readonly sanDnsNames?: readonly string[];
  readonly validFrom?: string;
  readonly validTo?: string;
  readonly fingerprintSha256?: string;
  readonly verified?: boolean;
}

export interface PageCaptureSecurityHeader {
  readonly name: string;
  readonly value: string;
}

export interface PageCaptureSiteMetadata {
  readonly contentType?: string;
  readonly contentLength?: number;
  readonly language?: string;
  readonly contentEncoding?: string;
  readonly serverProduct?: string;
  readonly technologies?: readonly string[];
  readonly securityHeaders?: readonly PageCaptureSecurityHeader[];
}

export interface PageCaptureArtifactReferenceInput {
  readonly artifactId: string;
  /** Lower-case SHA-256 of the immutable artifact bytes. */
  readonly sha256: string;
}

export interface PageCaptureArtifactProjection {
  readonly artifactId: string;
  readonly contentHash: string;
  readonly mediaType: string;
  readonly byteSize: number;
}

export interface PageCaptureRelatedRecords {
  readonly evidenceIds: readonly string[];
  readonly observationIds: readonly string[];
  readonly findingIds: readonly string[];
}

export interface CreatePageCaptureInput {
  readonly missionId: string;
  readonly runId: string;
  /** Required when stepId is supplied so the plan relationship is validated. */
  readonly planId?: string;
  readonly stepId?: string;
  readonly assetNodeId?: string;
  readonly serviceNodeId?: string;
  readonly url: string;
  readonly responseStatus: number;
  readonly title?: string;
  readonly viewport: PageCaptureViewport;
  readonly screenshot: PageCaptureArtifactReferenceInput;
  readonly fullPageScreenshot?: PageCaptureArtifactReferenceInput;
  readonly contentHash: string;
  readonly certificate?: PageCaptureCertificateMetadata;
  readonly site?: PageCaptureSiteMetadata;
  readonly capturedByAgentId: string;
  readonly captureTool: string;
  readonly sensitivity: Sensitivity;
  readonly redactionState: PageCaptureRedactionState;
  readonly capturedAt: string;
  readonly evidenceIds?: readonly string[];
  readonly observationIds?: readonly string[];
  readonly findingIds?: readonly string[];
}

export interface PageCaptureGalleryProjection {
  readonly label: string;
  /** Hidden while redaction is pending or the capture is quarantined. */
  readonly previewArtifactId: string | null;
  readonly fullPageArtifactId: string | null;
  readonly previewAvailable: boolean;
  readonly redactionState: PageCaptureRedactionState;
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
  readonly viewport: PageCaptureViewport;
  readonly screenshot?: PageCaptureArtifactProjection;
  readonly fullPageScreenshot?: PageCaptureArtifactProjection;
  readonly contentHash: string;
  readonly screenshotHash?: string;
  readonly fullPageScreenshotHash?: string;
  readonly certificate: PageCaptureCertificateMetadata;
  readonly site: PageCaptureSiteMetadata;
  readonly related: PageCaptureRelatedRecords;
  readonly capturedByAgentId?: string;
  readonly capturedByAgentName?: string;
  readonly captureTool: string;
  readonly sensitivity: Sensitivity;
  readonly redactionState: PageCaptureRedactionState;
  readonly capturedAt: string;
  readonly createdAt: string;
  readonly gallery: PageCaptureGalleryProjection;
}

export interface PageCaptureCursor {
  readonly capturedAt: string;
  readonly id: string;
}

export interface PageCaptureListFilter {
  readonly missionId: string;
  readonly runId?: string;
  readonly assetNodeId?: string;
  readonly serviceNodeId?: string;
  readonly redactionState?: PageCaptureRedactionState;
  readonly cursor?: PageCaptureCursor;
  readonly limit?: number;
}

export interface PageCaptureListPage {
  readonly items: readonly PageCaptureRecord[];
  readonly nextCursor?: string;
}

export class PageCaptureError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "PageCaptureError";
  }
}
