import { Router, type Request, type Response } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";

function unavailable(
  code: string,
  message: string,
  humanMessage: string,
  remediation: string,
) {
  return (request: Request, response: Response): void => {
    const traceId = attachV2RequestId(request, response);
    response.setHeader("Cache-Control", "no-store");
    sendV2Error(response, traceId, {
      status: 503,
      code,
      message,
      humanMessage,
      retryable: false,
      category: "dependency_missing",
      remediation,
    });
  };
}

/**
 * Explicit fail-closed contract for the standalone preview process. Read
 * projections remain usable, while documented mutation paths return a
 * diagnosable 503 instead of falling through to a misleading generated 404.
 */
export function createUnavailableExecutionRouter(): Router {
  const router = Router();
  const commanderUnavailable = unavailable(
    "guided_commander_runtime_unavailable",
    "Guided Commander mutation runtime is unavailable",
    "This V2 process has no callable planning-only Guided provider. The represented step remains paused and no Commander result was created.",
    "Connect a policy-compatible Guided provider and mount its planning-only runtime boundary, then recheck System readiness.",
  );
  const exactStepUnavailable = unavailable(
    "mission_runtime_mutation_unavailable",
    "Mission runtime mutation boundary is unavailable",
    "This V2 process exposes durable mission state read-only because no attested execution runtime is attached. No run or exact-step state changed.",
    "Connect the isolated V2 runtime and its enforced provider/MCP boundary, then recheck System readiness.",
  );

  for (const action of [
    "explain-more",
    "show-next-step",
    "interpret-result",
    "use-another-approach",
  ]) {
    router.post(`/api/v2/guided/:missionId/commander/${action}`, commanderUnavailable);
  }
  for (const action of ["approve", "reject", "manual-result", "skip", "stop"]) {
    router.post(`/api/v2/guided-decisions/:decisionId/${action}`, exactStepUnavailable);
  }
  for (const action of ["pause", "resume", "cancel"]) {
    router.post(`/api/v2/runs/:runId/${action}`, exactStepUnavailable);
  }
  return router;
}
