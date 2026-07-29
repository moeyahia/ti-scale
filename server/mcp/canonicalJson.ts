import { createHash } from "node:crypto";

export interface CanonicalJsonLimits {
  readonly maxBytes: number;
  readonly maxDepth: number;
}
export interface CanonicalJsonDigest {
  readonly canonicalJson: string;
  readonly sha256: string;
  readonly bytes: number;
}

export class CanonicalJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalJsonError";
  }
}

function encode(value: unknown, depth: number, maxDepth: number, ancestors: Set<object>): string {
  if (depth > maxDepth) {
    throw new CanonicalJsonError(`JSON value exceeds maximum depth ${maxDepth}`);
  }
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new CanonicalJsonError("JSON numbers must be finite");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new CanonicalJsonError(`Unsupported JSON value type: ${typeof value}`);
  }
  if (ancestors.has(value)) throw new CanonicalJsonError("Cyclic JSON values are not supported");

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((item) => encode(item, depth + 1, maxDepth, ancestors)).join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new CanonicalJsonError("Only plain JSON objects can be attested");
    }
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record).sort().map((key) => {
      const encodedKey = JSON.stringify(key);
      return `${encodedKey}:${encode(record[key], depth + 1, maxDepth, ancestors)}`;
    });
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function digestCanonicalJson(
  value: unknown,
  limits: CanonicalJsonLimits,
): CanonicalJsonDigest {
  const canonicalJson = encode(value, 0, limits.maxDepth, new Set());
  const bytes = Buffer.byteLength(canonicalJson, "utf8");
  if (bytes > limits.maxBytes) {
    throw new CanonicalJsonError(`Canonical JSON is ${bytes} bytes; limit is ${limits.maxBytes}`);
  }
  return {
    canonicalJson,
    sha256: createHash("sha256").update(canonicalJson, "utf8").digest("hex"),
    bytes,
  };
}
