import {
  findRejectableSecrets,
  findReusableContentIdentifiers,
  redactLessonText,
} from "./AttackLesson";

export interface CanonicalLearningAction {
  readonly id: string;
  readonly actionType: string;
  readonly actionClass: string;
  readonly normalizedArgumentsJson: string;
}

export interface CanonicalLearningToolCall {
  readonly id: string;
  readonly actionId: string;
  readonly toolName: string;
  readonly normalizedArgumentsJson: string;
}

export type ProjectionQuarantineReason =
  | "credential_value"
  | "identity_value"
  | "malformed_json"
  | "oversized_arguments"
  | "path_value"
  | "raw_command"
  | "target_or_box_identity"
  | "target_value";

export interface ProjectionQuarantine {
  readonly sourceType: "action" | "tool_call";
  readonly sourceId: string;
  readonly reasons: readonly ProjectionQuarantineReason[];
}

export interface SafeAttackChainProjection {
  readonly orderedSteps: readonly string[];
  readonly tools: readonly string[];
  readonly publicReferences: readonly string[];
  readonly antiReuseWarnings: readonly string[];
  readonly quarantined: readonly ProjectionQuarantine[];
}

interface ToolIdentity {
  readonly name: string;
  readonly reference: string;
}

interface SafeArguments {
  readonly semantics: readonly string[];
  readonly reasons: readonly ProjectionQuarantineReason[];
  readonly toolHint?: string;
}

const MAX_ARGUMENT_BYTES = 128 * 1024;
const RAW_COMMAND_KEY = /^(?:cmd|command|commandline|exec|execute|payload|scriptbody|shell|shellcommand)$/u;
const SECRET_KEY = /(?:api.?key|auth|bearer|cookie|credential|pass(?:word|wd)?|private.?key|secret|session|token)/u;
const USER_KEY = /^(?:account|login|user|userid|username)$/u;
const TARGET_KEY = /^(?:baseurl|domain|endpoint|host|hostname|ip|ipaddress|rhost|rhosts|target|targetdomain|targethost|targetip|targets|targeturl|url|uri)$/u;
const PATH_KEY = /^(?:directory|dir|file|filename|filepath|inputfile|inputpath|outputfile|outputpath|outfile|path|requestfile|savepath|wordlist|wordlistpath)$/u;
const PORT_KEY = /^(?:port|ports|rport)$/u;
const WORDLIST_KEY = /(?:dictionary|wordlist)/u;
const OUTPUT_KEY = /(?:output|outfile|save)/u;
const INPUT_KEY = /(?:input|requestfile)/u;
const RAW_COMMAND_VALUE = /(?:^|[\s;|&])(?:bash|cmd(?:\.exe)?|curl|ffuf|gobuster|hydra|nmap|nuclei|powershell|python\d*|sh|sqlmap|sudo|wget)(?:\s|$)|[`;$|]|&&|\|\|/iu;
const LITERAL_PATH_VALUE = /(?:^|\s)(?:\.{0,2}[\\/]|~[\\/]|[A-Za-z]:\\|\/(?:etc|home|opt|root|tmp|usr|var)(?:\/|$))/u;
const TARGET_VALUE = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9][a-z0-9.-]*\.(?:htb|internal|lan|local|test)\b|\b(?:hack\s*the\s*box|hackthebox|htb|tryhackme|vulnhub|ctf)\b/iu;
const SAFE_TOOL_NAME = /^[A-Za-z][A-Za-z0-9+_.:-]{0,80}$/u;

const TOOL_CATALOG: readonly { readonly signal: RegExp; readonly identity: ToolIdentity }[] = [
  { signal: /nmap/iu, identity: { name: "nmap", reference: "https://nmap.org/book/man.html" } },
  { signal: /ffuf/iu, identity: { name: "ffuf", reference: "https://github.com/ffuf/ffuf" } },
  { signal: /nuclei/iu, identity: { name: "nuclei", reference: "https://docs.projectdiscovery.io/tools/nuclei/overview" } },
  { signal: /impacket/iu, identity: { name: "Impacket", reference: "https://github.com/fortra/impacket" } },
  { signal: /netexec|\bnxc\b/iu, identity: { name: "NetExec", reference: "https://www.netexec.wiki/" } },
  { signal: /burp/iu, identity: { name: "Burp Suite", reference: "https://portswigger.net/burp/documentation" } },
  { signal: /sqlmap/iu, identity: { name: "sqlmap", reference: "https://github.com/sqlmapproject/sqlmap" } },
];

const FLAG_SEMANTICS: Readonly<Record<string, string>> = {
  "-o": "OS fingerprinting (-O)",
  "-pn": "host-discovery bypass only when the authorized scope requires it (-Pn)",
  "-sc": "the default safe script set (-sC)",
  "-ss": "TCP SYN scan mode (-sS)",
  "-st": "TCP connect scan mode (-sT)",
  "-su": "UDP scan mode (-sU)",
  "-sv": "service and version detection (-sV)",
  "--follow-redirects": "bounded redirect following",
  "--passive": "passive collection mode",
  "--recursive": "bounded recursive discovery",
  "--tech-detect": "technology fingerprinting",
};

const BOOLEAN_SEMANTICS: Readonly<Record<string, string>> = {
  active: "active collection within the authorized boundary",
  defaultscripts: "the default safe script set (-sC)",
  followredirects: "bounded redirect following",
  osdetection: "OS fingerprinting (-O)",
  passive: "passive collection mode",
  recursive: "bounded recursive discovery",
  sc: "the default safe script set (-sC)",
  servicedetection: "service and version detection (-sV)",
  ss: "TCP SYN scan mode (-sS)",
  st: "TCP connect scan mode (-sT)",
  su: "UDP scan mode (-sU)",
  sv: "service and version detection (-sV)",
  ssl: "TLS-enabled transport",
  techdetect: "technology fingerprinting",
  tls: "TLS-enabled transport",
  versiondetection: "service and version detection (-sV)",
};

const SAFE_PROTOCOLS: Readonly<Record<string, string>> = {
  dns: "DNS protocol selection",
  ftp: "FTP protocol selection",
  http: "HTTP protocol selection",
  https: "HTTPS protocol selection",
  kerberos: "Kerberos protocol selection",
  ldap: "LDAP protocol selection",
  smb: "SMB protocol selection",
  ssh: "SSH protocol selection",
  tcp: "TCP protocol selection",
  udp: "UDP protocol selection",
  winrm: "WinRM protocol selection",
};

const SAFE_HTTP_METHODS = new Set(["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]);
const SAFE_SEVERITIES = new Set(["critical", "high", "medium", "low", "info", "unknown"]);

function normalizedKey(key: string): string {
  return key.replace(/[^A-Za-z0-9]/gu, "").toLocaleLowerCase("en-US");
}

function add<T>(values: T[], value: T): void {
  if (!values.includes(value)) values.push(value);
}

function parseRecord(source: string): { record: Record<string, unknown>; reason?: ProjectionQuarantineReason } {
  if (Buffer.byteLength(source, "utf8") > MAX_ARGUMENT_BYTES) {
    return { record: {}, reason: "oversized_arguments" };
  }
  try {
    const value = JSON.parse(source) as unknown;
    return value && typeof value === "object" && !Array.isArray(value)
      ? { record: value as Record<string, unknown> }
      : { record: {}, reason: "malformed_json" };
  } catch {
    return { record: {}, reason: "malformed_json" };
  }
}

function stringValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function unsafeStringReason(value: string): ProjectionQuarantineReason | undefined {
  if (redactLessonText(value) !== value || findRejectableSecrets(value).length > 0) return "credential_value";
  if (LITERAL_PATH_VALUE.test(value)) return "path_value";
  if (RAW_COMMAND_VALUE.test(value)) return "raw_command";
  if (TARGET_VALUE.test(value) || findReusableContentIdentifiers(value).length > 0) return "target_or_box_identity";
  return undefined;
}

function recognizedFlags(value: unknown, reasons: ProjectionQuarantineReason[]): string[] {
  const raw = stringValues(value).join(" ").trim();
  if (!raw) return [];
  if (/[`;|&$]/u.test(raw)) {
    add(reasons, "raw_command");
    return [];
  }
  if (RAW_COMMAND_VALUE.test(raw)) add(reasons, "raw_command");
  if (LITERAL_PATH_VALUE.test(raw)) add(reasons, "path_value");
  if (TARGET_VALUE.test(raw) || findReusableContentIdentifiers(raw).length > 0) {
    add(reasons, "target_or_box_identity");
  }
  if (redactLessonText(raw) !== raw || findRejectableSecrets(raw).length > 0) {
    add(reasons, "credential_value");
  }
  const result: string[] = [];
  for (const token of raw.split(/[\s,]+/u)) {
    const semantic = FLAG_SEMANTICS[token.toLocaleLowerCase("en-US")];
    if (semantic) add(result, semantic);
  }
  return result;
}

function safeArguments(jsonSources: readonly string[]): SafeArguments {
  const semantics: string[] = [];
  const reasons: ProjectionQuarantineReason[] = [];
  let toolHint: string | undefined;

  const visit = (value: unknown, rawKey: string, depth: number): void => {
    if (depth > 8 || value === null || value === undefined) return;
    const key = normalizedKey(rawKey);
    if (RAW_COMMAND_KEY.test(key)) {
      if (typeof value === "string" && value.trim()) add(reasons, "raw_command");
      return;
    }
    if (SECRET_KEY.test(key)) {
      if (value !== "[REDACTED]" && value !== null && value !== "") add(reasons, "credential_value");
      add(semantics, "credentials supplied at execution time through <CREDENTIAL_REF>");
      return;
    }
    if (USER_KEY.test(key)) {
      if (value !== null && value !== "") add(reasons, "identity_value");
      add(semantics, "an authorized identity supplied through <USER_REF>");
      return;
    }
    if (TARGET_KEY.test(key)) {
      if (value !== null && value !== "") add(reasons, "target_value");
      add(semantics, "target binding through <TARGET_HOST>");
      return;
    }
    if (PORT_KEY.test(key)) {
      add(semantics, `port selection through <${key === "port" || key === "rport" ? "PORT" : "PORTS"}>`);
      return;
    }
    if (PATH_KEY.test(key)) {
      if (value !== null && value !== "") add(reasons, "path_value");
      const placeholder = WORDLIST_KEY.test(key)
        ? "<WORDLIST_PATH>"
        : OUTPUT_KEY.test(key)
          ? "<OUTPUT_PATH>"
          : INPUT_KEY.test(key)
            ? "<INPUT_PATH>"
            : "<INPUT_PATH>";
      add(semantics, `${WORDLIST_KEY.test(key) ? "wordlist" : OUTPUT_KEY.test(key) ? "output" : "file input"} binding through ${placeholder}`);
      return;
    }
    if (key === "toolname" && typeof value === "string" && SAFE_TOOL_NAME.test(value)) {
      toolHint = value;
      return;
    }
    if (key === "flags" || key === "options" || (key === "args" || key === "arguments") && typeof value === "string") {
      for (const semantic of recognizedFlags(value, reasons)) add(semantics, semantic);
      if ((key !== "args" && key !== "arguments") || typeof value === "string") return;
    }
    if (typeof value === "boolean") {
      if (value && BOOLEAN_SEMANTICS[key]) add(semantics, BOOLEAN_SEMANTICS[key]!);
      return;
    }
    if (typeof value === "string") {
      const unsafe = unsafeStringReason(value);
      if (unsafe) add(reasons, unsafe);
      if ((key === "protocol" || key === "service" || key === "transport") && SAFE_PROTOCOLS[value.toLocaleLowerCase("en-US")]) {
        add(semantics, SAFE_PROTOCOLS[value.toLocaleLowerCase("en-US")]!);
      } else if ((key === "method" || key === "httpmethod") && SAFE_HTTP_METHODS.has(value.toUpperCase())) {
        add(semantics, `HTTP ${value.toUpperCase()} method`);
      } else if (key === "severity") {
        const selected = value.split(/[\s,]+/u)
          .map((item) => item.toLocaleLowerCase("en-US"))
          .filter((item) => SAFE_SEVERITIES.has(item));
        if (selected.length) add(semantics, `severity filtering for ${[...new Set(selected)].join(" and ")}`);
      } else if (key === "headers" || key === "header") {
        add(semantics, "request headers supplied through protected execution input");
      } else if (key === "body" || key === "data" || key === "request") {
        add(semantics, "request content supplied through protected execution input");
      }
      return;
    }
    if (typeof value === "number") {
      if (key === "concurrency" || key === "threads" || key === "workers") add(semantics, "bounded specialist concurrency");
      if (key === "depth" || key === "maxdepth") add(semantics, "a reviewed discovery depth");
      if (key === "rate" || key === "ratelimit" || key === "requestspersecond") add(semantics, "a contract-bounded request rate");
      if (key === "retries" || key === "retry") add(semantics, "a bounded retry count");
      if (key === "timeout" || key === "timeoutms" || key === "timeoutseconds") add(semantics, "a bounded timeout");
      return;
    }
    if (Array.isArray(value)) {
      if (key === "severity" || key === "severities") {
        const selected = value.filter((item): item is string => typeof item === "string")
          .map((item) => item.toLocaleLowerCase("en-US"))
          .filter((item) => SAFE_SEVERITIES.has(item));
        if (selected.length) add(semantics, `severity filtering for ${[...new Set(selected)].join(" and ")}`);
        return;
      }
      if (key === "flags" || key === "options") {
        for (const semantic of recognizedFlags(value, reasons)) add(semantics, semantic);
        return;
      }
      value.forEach((item) => visit(item, rawKey, depth + 1));
      return;
    }
    if (typeof value === "object") {
      Object.entries(value as Record<string, unknown>).forEach(([childKey, child]) => visit(child, childKey, depth + 1));
    }
  };

  for (const source of jsonSources) {
    const parsed = parseRecord(source);
    if (parsed.reason) add(reasons, parsed.reason);
    Object.entries(parsed.record).forEach(([key, value]) => visit(value, key, 0));
  }
  return { semantics: semantics.slice(0, 10), reasons, ...(toolHint ? { toolHint } : {}) };
}

function safeTool(toolName: string | undefined): ToolIdentity {
  const candidate = toolName?.trim() ?? "";
  const known = TOOL_CATALOG.find((entry) => entry.signal.test(candidate));
  if (known) return known.identity;
  // Unknown tool labels are provenance, not trusted taxonomy. Never project an
  // arbitrary label into reusable memory: it may itself be a box, operator, or
  // target identity even when it happens to match a conservative token shape.
  return {
    name: "specialist-procedure",
    reference: "https://owasp.org/www-project-web-security-testing-guide/",
  };
}

function safeDomain(value: string): string {
  const normalized = value.toLocaleLowerCase("en-US");
  if (normalized.includes("recon")) return "reconnaissance";
  if (normalized.includes("enumerat")) return "enumeration";
  if (normalized.includes("evidence")) return "evidence collection";
  if (normalized.includes("validat")) return "validation";
  if (normalized.includes("analys")) return "analysis";
  if (normalized.includes("report")) return "reporting";
  if (normalized.includes("recover")) return "recovery";
  return "specialist execution";
}

function assertSafeGeneratedText(text: string): void {
  if (
    findRejectableSecrets(text).length > 0 ||
    redactLessonText(text) !== text ||
    findReusableContentIdentifiers(text).length > 0 ||
    LITERAL_PATH_VALUE.test(text.replace(/<[^>]+>/gu, "")) ||
    /[`;$|]|&&|\|\|/u.test(text)
  ) {
    throw new Error("safe attack-chain projection produced reusable-content leakage");
  }
}

/**
 * Convert canonical action/tool-call records into reusable, parameterized
 * technique reminders. Source values are inspected only to classify option
 * semantics; literal values are never interpolated into output.
 */
export function projectSafeAttackChain(input: {
  readonly actions: readonly CanonicalLearningAction[];
  readonly toolCalls: readonly CanonicalLearningToolCall[];
  readonly fallbackDomain: string;
}): SafeAttackChainProjection {
  const tools: string[] = [];
  const references: string[] = [];
  const orderedSteps: string[] = [];
  const quarantined: ProjectionQuarantine[] = [];
  const callsByAction = new Map<string, CanonicalLearningToolCall[]>();
  for (const call of input.toolCalls) {
    const existing = callsByAction.get(call.actionId) ?? [];
    existing.push(call);
    callsByAction.set(call.actionId, existing);
  }

  for (const action of input.actions) {
    const calls = callsByAction.get(action.id) ?? [];
    const sources = calls.length > 0 ? calls : [undefined];
    for (const call of sources) {
      const actionArgs = safeArguments([action.normalizedArgumentsJson]);
      const callArgs = call ? safeArguments([call.normalizedArgumentsJson]) : undefined;
      const semantics = [...actionArgs.semantics];
      for (const semantic of callArgs?.semantics ?? []) add(semantics, semantic);
      const identity = safeTool(call?.toolName ?? callArgs?.toolHint ?? actionArgs.toolHint);
      const domain = safeDomain(action.actionClass || action.actionType || input.fallbackDomain);
      add(tools, identity.name);
      add(references, identity.reference);
      const configuration = semantics.length > 0
        ? ` Configure ${semantics.slice(0, 10).join(", ")}.`
        : " Bind reviewed parameters at execution time.";
      const step = `Use ${identity.name} through the assigned specialist for bounded ${domain} against <TARGET_HOST>.${configuration} Retain the result as immutable evidence before advancing.`;
      assertSafeGeneratedText(step);
      add(orderedSteps, step);
      if (actionArgs.reasons.length > 0) {
        quarantined.push({
          sourceType: "action",
          sourceId: action.id,
          reasons: actionArgs.reasons,
        });
      }
      if (call && callArgs && callArgs.reasons.length > 0) quarantined.push({
        sourceType: "tool_call",
        sourceId: call.id,
        reasons: callArgs.reasons,
      });
    }
  }

  if (orderedSteps.length === 0) {
    const identity = safeTool(undefined);
    const step = `Use ${identity.name} through the assigned specialist for bounded ${safeDomain(input.fallbackDomain)} against <TARGET_HOST>. Bind reviewed parameters at execution time. Retain the result as immutable evidence before advancing.`;
    assertSafeGeneratedText(step);
    orderedSteps.push(step);
    tools.push(identity.name);
    references.push(identity.reference);
  }

  const antiReuseWarnings = [
    "Do not reuse the chain when authorization, scope, prerequisites, or observed signals differ",
  ];
  if (quarantined.length > 0) {
    antiReuseWarnings.push(
      "Target, path, identity, credential, raw-command, or unsafe source values were quarantined. Bind reviewed placeholders at execution time",
    );
  }
  for (const text of [...orderedSteps, ...tools, ...antiReuseWarnings]) assertSafeGeneratedText(text);
  return { orderedSteps, tools, publicReferences: references, antiReuseWarnings, quarantined };
}
