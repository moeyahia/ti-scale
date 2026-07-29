import { parseCapabilitySelfTestSnapshot } from "../../domain/schemas/capabilitySelfTests";
import type { CapabilitySelfTestSnapshot } from "../../domain/types/capabilitySelfTests";
import { apiRequest } from "./client";

export const CAPABILITY_SELF_TEST_ENDPOINT = "/api/v2/system/capability-self-tests";

export function fetchCapabilitySelfTests(signal?: AbortSignal): Promise<CapabilitySelfTestSnapshot> {
  return apiRequest(CAPABILITY_SELF_TEST_ENDPOINT, {
    method: "GET",
    signal,
    parse: parseCapabilitySelfTestSnapshot,
  });
}
