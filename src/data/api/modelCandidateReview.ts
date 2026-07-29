import { apiRequest } from "./client";
import { parseModelCandidateReview } from "../../domain/schemas/modelCandidateReview";
import type { ModelCandidateReview } from "../../domain/types/modelCandidateReview";

let reviewRequest: Promise<ModelCandidateReview> | undefined;

/** One bounded request across React development Strict Mode's mount probe. */
export function fetchModelCandidateReview(): Promise<ModelCandidateReview> {
  reviewRequest ??= apiRequest("/api/v2/motion-lab/review", {
    method: "GET",
    parse: parseModelCandidateReview,
  });
  void reviewRequest.catch(() => { reviewRequest = undefined; });
  return reviewRequest;
}
