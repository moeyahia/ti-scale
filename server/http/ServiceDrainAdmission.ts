import type { RequestHandler } from "express";
import { attachV2RequestId, sendV2Error } from "../contracts";

/**
 * Synchronous process-wide admission fence for shutdown. It is independent of
 * listener closure because HTTP/1.1 keep-alive connections can already be
 * accepted when SIGTERM arrives.
 */
export class ServiceDrainAdmission {
  #draining = false;

  get draining(): boolean {
    return this.#draining;
  }

  beginDrain(): void {
    this.#draining = true;
  }

  readonly middleware: RequestHandler = (request, response, next): void => {
    if (!this.#draining) {
      next();
      return;
    }
    response.setHeader("Connection", "close");
    const traceId = attachV2RequestId(request, response);
    sendV2Error(response, traceId, {
      status: 503,
      code: "ti_scale_service_draining",
      message: "Ti-Scale is draining",
      humanMessage: "Ti-Scale is shutting down and is not accepting new work.",
      retryable: true,
      category: "service_unavailable",
      remediation: "Wait for the supervised service restart and retry this request.",
    });
  };
}
