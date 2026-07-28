export type ModelCandidateReviewStatus = "candidate" | "rejected" | "approved";
export type ModelCandidateReviewAssetKind = "source-image" | "turntable-image" | "model-glb";

export interface ModelCandidateReviewAsset {
  readonly id: string;
  readonly kind: ModelCandidateReviewAssetKind;
  readonly label: string;
  readonly description: string;
  readonly mimeType: "image/png" | "image/jpeg" | "model/gltf-binary";
  readonly bytes: number;
  readonly sha256: string;
  readonly url: string;
  readonly width?: number;
  readonly height?: number;
  readonly triangleCount?: number;
  readonly vertexCount?: number;
}

export interface AvailableModelCandidateReview {
  readonly schemaVersion: 1;
  readonly availability: "available";
  readonly candidateId: string;
  readonly status: ModelCandidateReviewStatus;
  readonly reviewState: "unreviewed" | "rejected" | "approved";
  readonly title: string;
  readonly summary: string;
  readonly generatedAt: string;
  readonly provenance: {
    readonly imageTaskId: string;
    readonly modelTaskId: string;
    readonly imageCredits: number;
    readonly modelCredits: number;
  };
  readonly approval: {
    readonly authority: "operator";
    readonly receiptId: string | null;
    readonly decidedAt: string | null;
  };
  readonly assets: readonly ModelCandidateReviewAsset[];
}

export interface UnconfiguredModelCandidateReview {
  readonly schemaVersion: 1;
  readonly availability: "not_configured";
  readonly humanMessage: string;
  readonly remediation: string;
}

export type ModelCandidateReview = AvailableModelCandidateReview | UnconfiguredModelCandidateReview;
