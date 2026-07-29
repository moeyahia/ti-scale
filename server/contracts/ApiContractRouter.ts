import { Router } from "express";
import {
  COMMAND_OS_EVENT_DELIVERY_CONTRACT,
  createCommandOsOpenApiDocument,
} from "./v2Contract";
import { attachV2RequestId } from "./ApiErrorContract";

/** Publishes the checked V2 API/event contract from the running application. */
export function createApiContractRouter(): Router {
  const router = Router();
  const openApi = createCommandOsOpenApiDocument();

  router.use((request, response, next) => {
    attachV2RequestId(request, response);
    response.setHeader("Cache-Control", "no-store");
    next();
  });
  router.get("/api/v2/openapi.json", (_request, response) => {
    response.json(openApi);
  });
  router.get("/api/v2/contracts/events", (_request, response) => {
    response.json(COMMAND_OS_EVENT_DELIVERY_CONTRACT);
  });

  return router;
}
