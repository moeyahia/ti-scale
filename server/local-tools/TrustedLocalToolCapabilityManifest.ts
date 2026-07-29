import {
  loadTrustedJson,
  type LoadedTrustedJson,
  type TrustedJsonFileReference,
} from "../trusted-runtime-config/TrustedJsonFileLoader";
import {
  LocalToolCapabilityManifest,
  parseLocalToolCapabilityManifestDocument,
} from "./LocalToolCapabilityManifest";

const LOCAL_TOOL_CAPABILITY_MANIFEST_MAXIMUM_BYTES = 2 * 1_024 * 1_024;

/**
 * Loads one operator-reviewed local-tool document through the same immutable,
 * no-symlink, pinned-hash boundary as the other production runtime sources.
 * Loading configuration performs no executable probe and grants no authority.
 */
export function loadTrustedLocalToolCapabilityManifest(
  reference: TrustedJsonFileReference,
): LoadedTrustedJson<LocalToolCapabilityManifest> {
  if (reference.maximumBytes !== undefined
    && reference.maximumBytes > LOCAL_TOOL_CAPABILITY_MANIFEST_MAXIMUM_BYTES) {
    throw new Error("Local tool capability manifest maximumBytes exceeds 2097152");
  }
  const loaded = loadTrustedJson(
    {
      ...reference,
      maximumBytes: reference.maximumBytes ?? LOCAL_TOOL_CAPABILITY_MANIFEST_MAXIMUM_BYTES,
    },
    parseLocalToolCapabilityManifestDocument,
  );
  return {
    value: new LocalToolCapabilityManifest(loaded.value),
    receipt: loaded.receipt,
  };
}
