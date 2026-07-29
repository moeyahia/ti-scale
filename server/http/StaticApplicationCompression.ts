import compression from "compression";
import { constants as zlibConstants } from "node:zlib";

const API_PATH = /^\/api(?:\/|$)/u;
const EVENT_STREAM_CONTENT_TYPE = /^text\/event-stream(?:;|$)/iu;

export const STATIC_COMPRESSION_THRESHOLD_BYTES = 1_024;
export const STATIC_BROTLI_QUALITY = 5;

function isEventStream(contentType: unknown): boolean {
  return typeof contentType === "string"
    && EVENT_STREAM_CONTENT_TYPE.test(contentType.trim());
}

/**
 * Compresses only browser-shell/static responses.
 *
 * The application mounts this after every API router, but the filter also
 * rejects API paths and event streams. This keeps live SSE semantics intact
 * if static middleware ordering changes in a future server composition.
 */
export function createStaticApplicationCompression() {
  return compression({
    threshold: STATIC_COMPRESSION_THRESHOLD_BYTES,
    brotli: {
      params: {
        [zlibConstants.BROTLI_PARAM_QUALITY]: STATIC_BROTLI_QUALITY,
      },
    },
    filter(request, response) {
      if (API_PATH.test(request.path)) return false;
      if (isEventStream(response.getHeader("Content-Type"))) return false;
      return compression.filter(request, response);
    },
  });
}
