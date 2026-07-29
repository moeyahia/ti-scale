import { Router, type Request } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts/ApiErrorContract";
import type { CapabilitySelfTestService } from "./CapabilitySelfTestService";

const ACTOR_ID = /^[A-Za-z0-9._:@/-]{1,128}$/u;

export interface CapabilitySelfTestRouterOptions {
  readonly service: CapabilitySelfTestService;
  /** Resolved only from the trusted local authentication boundary. */
  readonly resolveActor: (request: Request) => string | undefined;
}

/** Authenticated, read-only dependency snapshot. It never initiates a probe. */
export function createCapabilitySelfTestRouter(
  options: CapabilitySelfTestRouterOptions,
): Router {
  const router = Router();
  router.get("/api/v2/system/capability-self-tests", (request, response) => {
    response.setHeader("Cache-Control", "no-store");
    const traceId = attachV2RequestId(request, response);
    let actorId = "";
    try {
      actorId = options.resolveActor(request)?.trim() ?? "";
    } catch {
      actorId = "";
    }
    if (!ACTOR_ID.test(actorId)) {
      response.setHeader("WWW-Authenticate", "Bearer realm=\"ti-scale\"");
      sendV2Error(response, traceId, {
        status: 401,
        code: "ti_scale_authentication_required",
        message: "A valid Ti-Scale operator session is required",
        humanMessage: "Sign in to inspect capability readiness.",
        retryable: false,
        category: "authentication_missing",
      });
      return;
    }
    try {
      response.json(options.service.snapshot());
    } catch {
      sendV2Error(response, traceId, {
        status: 503,
        code: "capability_self_test_unavailable",
        message: "Capability readiness could not be read safely",
        humanMessage: "Ti-Scale could not establish a safe dependency snapshot.",
        retryable: true,
        category: "dependency_missing",
        remediation: "Inspect redacted local readiness diagnostics and restore the canonical registry reader before retrying.",
      });
    }
  });
  return router;
}
