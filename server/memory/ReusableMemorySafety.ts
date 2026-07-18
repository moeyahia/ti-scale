/**
 * Fail-closed content boundary for reusable Second Brain records.
 *
 * Immutable evidence remains in the evidence store and is linked here by an
 * opaque ID. Credential values, authentication material, and raw confidential
 * payloads are never valid reusable-memory content, regardless of which API,
 * service, importer, or repository caller supplied them.
 */

export const REUSABLE_MEMORY_LIMITS = Object.freeze({
  title: 500,
  summary: 4_000,
  body: 64 * 1024,
  provenanceExplanation: 2_000,
  provenanceExcerpt: 4_000,
  provenanceIdentifier: 512,
  provenance: 32 * 1024,
  retentionPolicy: 16 * 1024,
  contextMetadata: 16 * 1024,
  vaultNote: 128 * 1024,
});

export type ReusableMemorySecretCategory =
  | "private_key"
  | "authorization_header"
  | "credential_assignment"
  | "credential_hash"
  | "session_material"
  | "signed_token"
  | "provider_token"
  | "cloud_access_key"
  | "credential_url";

export interface ReusableMemoryTextField {
  readonly field: string;
  readonly value: string | undefined | null;
  readonly maximumBytes: number;
}

export interface ReusableMemorySafetyDetails {
  readonly fields: readonly string[];
  readonly reasonCategories: readonly string[];
}

/** Error metadata is intentionally category-only and never includes input. */
export class ReusableMemorySafetyError extends TypeError {
  readonly status: number;
  readonly code: string;
  readonly category = "policy_denied";
  readonly humanMessage: string;
  readonly remediation: string;
  readonly details: ReusableMemorySafetyDetails;

  constructor(input: {
    readonly status: number;
    readonly code: string;
    readonly humanMessage: string;
    readonly remediation: string;
    readonly fields: readonly string[];
    readonly reasonCategories: readonly string[];
  }) {
    super(input.humanMessage);
    this.name = "ReusableMemorySafetyError";
    this.status = input.status;
    this.code = input.code;
    this.humanMessage = input.humanMessage;
    this.remediation = input.remediation;
    this.details = {
      fields: [...new Set(input.fields)].sort(),
      reasonCategories: [...new Set(input.reasonCategories)].sort(),
    };
  }
}

const PLACEHOLDER = /^(?:\[(?:REDACTED(?:[-_ ](?:AUTHENTICATION[-_ ]MATERIAL|KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL))?|MASKED)\]|<(?:PASSWORD|PASSWD|PASSPHRASE|TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|API_KEY|SECRET|CLIENT_SECRET|PRIVATE_KEY|SESSION_ID|SESSION_TOKEN|COOKIE|CREDENTIAL|CREDENTIAL_REF)>|\$\{[A-Z][A-Z0-9_]{1,127}\}|\$[A-Z][A-Z0-9_]{1,127}|(?:YOUR|EXAMPLE|PLACEHOLDER|REDACTED|MASKED|NOT_SET|NONE)(?:[-_][A-Z0-9]+)*)$/iu;

function unquote(value: string): string {
  const trimmed = value.trim().replace(/[),.;]+$/u, "");
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed.at(-1);
    if ((first === '"' && last === '"') || (first === "'" && last === "'") || (first === "`" && last === "`")) {
      return trimmed.slice(1, -1).trim();
    }
  }
  return trimmed;
}

function isSafePlaceholder(value: string): boolean {
  const normalized = unquote(value);
  if (PLACEHOLDER.test(normalized)) return true;
  return /^(?:authentication|authorization|bearer|basic|credentials?|headers?|scheme|workflow|policy|mechanism|placeholder|example|used|required|rotated|managed|stored|supplied|provided|requested|configured|disabled|enabled|hashed|reset|protected|exposed|never|not)$/iu.test(normalized);
}

interface CategorizedPattern {
  readonly category: ReusableMemorySecretCategory;
  readonly expression: RegExp;
  readonly valueGroup?: number;
}

const SECRET_PATTERNS: readonly CategorizedPattern[] = [
  {
    category: "private_key",
    expression: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----|$)/giu,
  },
  {
    category: "authorization_header",
    expression: /\b(?:authorization\s*:\s*)?(?:bearer|basic)\s+([A-Za-z0-9+/=_\-.]{8,})/giu,
    valueGroup: 1,
  },
  {
    category: "credential_assignment",
    expression: /(?:^|[^\p{L}\p{N}_])(?:["']?)(?:password|passwd|pwd|passphrase|api[ _-]?key|client[ _-]?secret|private[ _-]?key|credential|secret)(?:["']?)\s*(?::|=|\bis\b|\bwas\b)\s*("[^"]*"|'[^']*'|`[^`]*`|[^\s,;]+)/gimu,
    valueGroup: 1,
  },
  {
    category: "session_material",
    expression: /(?:^|[^\p{L}\p{N}_])(?:["']?)(?:token|access[ _-]?token|refresh[ _-]?token|auth[ _-]?token|id[ _-]?token|session[ _-]?(?:id|token|key)|oauth[ _-]?(?:code|token)|authorization(?:[ _-]?code)?|cookie|set-cookie)(?:["']?)\s*(?::|=|\bis\b|\bwas\b)\s*("[^"]*"|'[^']*'|`[^`]*`|[^\s,;]+)/gimu,
    valueGroup: 1,
  },
  {
    category: "credential_assignment",
    expression: /--(?:password|passwd|passphrase|api-key|token|secret|client-secret)\s+("[^"]*"|'[^']*'|`[^`]*`|[^\s,;]+)/giu,
    valueGroup: 1,
  },
  {
    category: "credential_hash",
    expression: /\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b/gu,
    valueGroup: 1,
  },
  {
    category: "credential_hash",
    expression: /(?:^|[^\p{L}\p{N}_])(?:["']?)(?:ntlm|nthash|lmhash|password[ _-]?hash|passwd[ _-]?hash)(?:["']?)\s*[:=]\s*([a-fA-F0-9]{32,128})\b/gimu,
    valueGroup: 1,
  },
  {
    category: "credential_hash",
    expression: /(\$(?:2[aby]|argon2(?:i|d|id)|[156])\$[A-Za-z0-9./$=+_-]{20,})/giu,
    valueGroup: 1,
  },
  {
    category: "signed_token",
    expression: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})\b/gu,
    valueGroup: 1,
  },
  {
    category: "cloud_access_key",
    expression: /\b((?:AKIA|ASIA)[A-Z0-9]{16})\b/gu,
    valueGroup: 1,
  },
  {
    category: "provider_token",
    expression: /\b((?:sk-(?:ant-)?|sk_|xai[-_]|gh[pousr]_|github_pat_|xox[baprs]-|AIza)[A-Za-z0-9_-]{12,})\b/gu,
    valueGroup: 1,
  },
  {
    category: "credential_url",
    expression: /\b([a-z][a-z0-9+.-]*:\/\/[^\s/@:]+:[^\s/@]+@[^\s/]+(?:\/[^\s]*)?)/giu,
    valueGroup: 1,
  },
];

/** Returns only safe classifications; matched values never leave this function. */
export function findReusableMemorySecretCategories(source: string): readonly ReusableMemorySecretCategory[] {
  const normalized = source.normalize("NFKC");
  const categories = new Set<ReusableMemorySecretCategory>();
  for (const pattern of SECRET_PATTERNS) {
    pattern.expression.lastIndex = 0;
    for (const match of normalized.matchAll(pattern.expression)) {
      const candidate = pattern.valueGroup === undefined ? undefined : match[pattern.valueGroup];
      if (candidate !== undefined && isSafePlaceholder(candidate)) continue;
      categories.add(pattern.category);
    }
  }
  return [...categories].sort();
}

/** Safe diagnostic redaction for boundaries that must display imported text. */
export function redactReusableMemorySecrets(source: string): { text: string; redactionCount: number } {
  let text = source.replace(/\0/gu, "");
  let redactionCount = 0;
  for (const pattern of SECRET_PATTERNS) {
    pattern.expression.lastIndex = 0;
    text = text.replace(pattern.expression, (...args: unknown[]) => {
      const match = String(args[0] ?? "");
      const candidate = pattern.valueGroup === undefined ? undefined : String(args[pattern.valueGroup] ?? "");
      if (candidate !== undefined && isSafePlaceholder(candidate)) return match;
      redactionCount += 1;
      return "[REDACTED AUTHENTICATION MATERIAL]";
    });
  }
  return { text, redactionCount };
}

export function assertReusableMemoryText(fields: readonly ReusableMemoryTextField[]): void {
  const oversized: string[] = [];
  const unsafe: string[] = [];
  const categories = new Set<string>();
  for (const field of fields) {
    if (field.value === undefined || field.value === null) continue;
    if (Buffer.byteLength(field.value, "utf8") > field.maximumBytes) oversized.push(field.field);
    if (field.value.includes("\0")) {
      unsafe.push(field.field);
      categories.add("invalid_control_character");
    }
    const detected = findReusableMemorySecretCategories(field.value);
    if (detected.length > 0) unsafe.push(field.field);
    detected.forEach((category) => categories.add(category));
  }
  if (oversized.length > 0) {
    throw new ReusableMemorySafetyError({
      status: 413,
      code: "reusable_memory_content_too_large",
      humanMessage: "Reusable memory content exceeds the safe retention limit.",
      remediation: "Retain the full payload as a protected artifact or immutable evidence record and link it by ID.",
      fields: oversized,
      reasonCategories: ["size_limit"],
    });
  }
  if (unsafe.length > 0) {
    throw new ReusableMemorySafetyError({
      status: 422,
      code: "sensitive_material_not_retained",
      humanMessage: "Reusable memory cannot contain credentials or authentication material.",
      remediation: "Remove the sensitive value and link protected evidence or credentials by an opaque ID.",
      fields: unsafe,
      reasonCategories: [...categories],
    });
  }
}

export function assertReusableMemoryUnknown(value: unknown, field: string, maximumBytes: number): void {
  let serialized: string;
  try {
    serialized = JSON.stringify(value) ?? "null";
  } catch {
    throw new ReusableMemorySafetyError({
      status: 400,
      code: "invalid_reusable_memory_metadata",
      humanMessage: "Reusable memory metadata must be finite JSON data.",
      remediation: "Remove cyclic or unsupported values before retaining this memory.",
      fields: [field],
      reasonCategories: ["invalid_json"],
    });
  }
  assertReusableMemoryText([{ field, value: serialized, maximumBytes }]);
}
