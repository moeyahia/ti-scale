import { createHash, createHmac } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { basename, extname, relative } from "node:path";
import { inImmediateTransaction, type SqliteDatabase } from "../db";
import { AuditTrailWriter } from "../intelligence-v24/AuditTrailWriter";
import {
  findReusableMemorySecretCategories,
  type AttackCentricReusableNodeType,
} from "../memory";
import { canonicalJson } from "../orchestration/serialization";
import {
  AttackKnowledgeCompiler,
  type AttackKnowledgeReconciliation,
  type ReusableAttackBundleKnowledge,
  type ReusableAttackFactKnowledge,
} from "./AttackKnowledgeCompiler";
import type {
  LegacyEngagementFile,
  LegacyEngagementManifest,
} from "./LegacyEngagementDiscovery";
import { containsHardSecret } from "./SecretSafety";

const DEFAULT_MAX_FILES = 2_000;
const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024;
const DEFAULT_MAX_FACTS_PER_FILE = 128;
const SHA256 = /^[a-f0-9]{64}$/u;
const ELIGIBLE_KINDS = new Set(["note", "report", "recon", "script", "evidence", "log"]);
const TEXT_EXTENSIONS = new Set([
  ".txt", ".md", ".json", ".jsonl", ".xml", ".csv", ".yaml", ".yml",
  ".html", ".htm", ".nmap", ".gnmap", ".log", ".py", ".sh", ".ps1",
  ".js", ".ts", ".rb", ".go", ".c", ".cpp", ".conf", ".ini",
]);
const SUMMARY_LOG_NAME = /(?:summary|status|checkpoint|result|timeline|next[-_ ]?actions|blocker|recovery)/iu;
const MALFORMED_TEXT = /\0|\uFFFD/u;

class PinnedSourceChangedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PinnedSourceChangedError";
  }
}

interface PinnedSourceExpectation {
  readonly sourceHash: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly sourceDevice?: number;
  readonly sourceInode?: number;
}

/** Read one immutable inode. O_NOFOLLOW prevents a final-component symlink,
 * while fstat before/after and the content hash detect replacement or writes. */
function readPinnedSource(path: string, expected: PinnedSourceExpectation): Buffer {
  const descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() ||
        (expected.sourceDevice !== undefined && before.dev !== expected.sourceDevice) ||
        (expected.sourceInode !== undefined && before.ino !== expected.sourceInode) ||
        before.size !== expected.byteSize ||
        before.mtime.toISOString() !== expected.modifiedAt) {
      throw new PinnedSourceChangedError("Private historical source identity changed before pinned read");
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size ||
        after.mtimeMs !== before.mtimeMs || bytes.byteLength !== expected.byteSize ||
        sha256(bytes) !== expected.sourceHash) {
      throw new PinnedSourceChangedError("Private historical source changed during pinned read");
    }
    const pathAfter = lstatSync(path);
    if (!pathAfter.isFile() || pathAfter.isSymbolicLink() ||
        pathAfter.dev !== after.dev || pathAfter.ino !== after.ino ||
        pathAfter.size !== after.size || pathAfter.mtimeMs !== after.mtimeMs) {
      throw new PinnedSourceChangedError("Private historical source path changed during pinned read");
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

type Fact = Readonly<{
  nodeType: AttackCentricReusableNodeType;
  title: string;
  summary: string;
  body: string;
  confidence: number;
}>;

type ProductPattern = Readonly<{
  expression: RegExp;
  name: string;
  nodeType: Extract<AttackCentricReusableNodeType,
    "technology_product" | "operating_system" | "kernel" | "framework" |
    "runtime" | "database" | "firewall" | "waf" | "proxy" | "security_control">;
}>;

const PRODUCT_PATTERNS: readonly ProductPattern[] = [
  { expression: /\bFreePBX(?: Administration)?(?:\/|\s+)(\d+(?:\.\d+){1,3}(?:[-+._a-z0-9]*)?)/giu, name: "FreePBX", nodeType: "technology_product" },
  { expression: /\bCheckmk Agent(?:\/|\s+)(\d+(?:\.\d+){1,3}(?:p\d+)?)/giu, name: "Checkmk Agent", nodeType: "technology_product" },
  { expression: /\bneedrestart(?:\/|\s+)(\d+(?:\.\d+){1,3}(?:[-+._a-z0-9]*)?)/giu, name: "needrestart", nodeType: "technology_product" },
  { expression: /\bApache(?: HTTP Server| httpd)?[ /](\d+(?:\.\d+){1,3}(?:[-+._a-z0-9]*)?)/giu, name: "Apache HTTP Server", nodeType: "technology_product" },
  { expression: /\bnginx(?:\/|\s+)(\d+(?:\.\d+){1,3}(?:[-+._a-z0-9]*)?)/giu, name: "nginx", nodeType: "technology_product" },
  { expression: /\bMicrosoft[- ]IIS(?:\/|\s+| httpd\s+)(\d+(?:\.\d+){1,3})/giu, name: "Microsoft IIS", nodeType: "technology_product" },
  { expression: /\b(?:Apache )?Tomcat(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Apache Tomcat", nodeType: "technology_product" },
  { expression: /\bJetty(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Eclipse Jetty", nodeType: "technology_product" },
  { expression: /\bWordPress(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "WordPress", nodeType: "technology_product" },
  { expression: /\bJenkins(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Jenkins", nodeType: "technology_product" },
  { expression: /\bGitLab(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "GitLab", nodeType: "technology_product" },
  { expression: /\bGrafana(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Grafana", nodeType: "technology_product" },
  { expression: /\bSamba(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Samba", nodeType: "technology_product" },
  { expression: /\bOpenLDAP(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "OpenLDAP", nodeType: "technology_product" },
  { expression: /\bOpenSSL(?:\/|\s+)(\d+(?:\.\d+){1,3}[a-z]?)/giu, name: "OpenSSL", nodeType: "technology_product" },
  { expression: /\bOpenSSH[_ /](\d+(?:\.\d+){1,3}(?:p\d+)?)/giu, name: "OpenSSH", nodeType: "technology_product" },
  { expression: /\bPHP(?:\/|\s+)(\d+(?:\.\d+){1,3}(?:[-+._a-z0-9]*)?)/giu, name: "PHP", nodeType: "runtime" },
  { expression: /\bASP\.NET(?: Core)?(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "ASP.NET", nodeType: "framework" },
  { expression: /\bNode\.js(?:\/|\s+v?)(\d+(?:\.\d+){1,3})/giu, name: "Node.js", nodeType: "runtime" },
  { expression: /\bPython(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Python", nodeType: "runtime" },
  { expression: /\b(?:OpenJDK|Java)(?:\/|\s+)(\d+(?:\.\d+){0,3})/giu, name: "Java", nodeType: "runtime" },
  { expression: /\bV8(?: JavaScript engine)?(?:\s+d8)?(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "V8 JavaScript engine", nodeType: "runtime" },
  { expression: /\b\.NET(?: Core)?(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: ".NET", nodeType: "runtime" },
  { expression: /\bExpress(?:\.js)?(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Express.js", nodeType: "framework" },
  { expression: /\bDjango(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Django", nodeType: "framework" },
  { expression: /\bFlask(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Flask", nodeType: "framework" },
  { expression: /\bRuby on Rails(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Ruby on Rails", nodeType: "framework" },
  { expression: /\bSpring Boot(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Spring Boot", nodeType: "framework" },
  { expression: /\bMySQL(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "MySQL", nodeType: "database" },
  { expression: /\bMariaDB(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "MariaDB", nodeType: "database" },
  { expression: /\bPostgreSQL(?:\/|\s+)(\d+(?:\.\d+){0,3})/giu, name: "PostgreSQL", nodeType: "database" },
  { expression: /\bMicrosoft SQL Server(?:\/|\s+)(\d+(?:\.\d+){0,3})/giu, name: "Microsoft SQL Server", nodeType: "database" },
  { expression: /\bRedis(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Redis", nodeType: "database" },
  { expression: /\bMongoDB(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "MongoDB", nodeType: "database" },
  { expression: /\bElasticsearch(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Elasticsearch", nodeType: "database" },
  { expression: /\bSQLite(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "SQLite", nodeType: "database" },
  { expression: /\bLinux(?: kernel)?(?:\/|\s+)(\d+\.\d+\.\d+(?:[-+._a-z0-9]*)?)/giu, name: "Linux kernel", nodeType: "kernel" },
  { expression: /\bWindows Server(?:\/|\s+)(20\d{2}(?:\s+(?:Build|revision)\s+\d+(?:\.\d+){0,3})?)/giu, name: "Windows Server", nodeType: "operating_system" },
  { expression: /\b(?:ntoskrnl(?:\.exe)?|Windows kernel(?: image)?)(?:\s+(?:FileVersion|ProductVersion|version|build))?(?:\s*[:=]?\s*)(10\.0\.\d+(?:\.\d+){1,2})/giu, name: "Windows kernel image", nodeType: "kernel" },
  { expression: /\bUbuntu(?: Linux)?(?:\/|\s+)(\d{2}\.\d{2})/giu, name: "Ubuntu", nodeType: "operating_system" },
  { expression: /\bDebian(?: GNU\/Linux)?(?:\/|\s+)(\d+(?:\.\d+){0,2})/giu, name: "Debian", nodeType: "operating_system" },
  { expression: /\bModSecurity(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "ModSecurity", nodeType: "waf" },
  { expression: /\bHAProxy(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "HAProxy", nodeType: "proxy" },
  { expression: /\bSquid(?: proxy)?(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Squid", nodeType: "proxy" },
  { expression: /\bpfSense(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "pfSense", nodeType: "firewall" },
  { expression: /\bFortiOS(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "FortiOS", nodeType: "firewall" },
  { expression: /\bPAN-OS(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "PAN-OS", nodeType: "firewall" },
  { expression: /\bDocker(?: Engine)?(?:\/|\s+)(\d+(?:\.\d+){1,3})/giu, name: "Docker Engine", nodeType: "runtime" },
  { expression: /\bKubernetes(?:\/|\s+v?)(\d+(?:\.\d+){1,3})/giu, name: "Kubernetes", nodeType: "runtime" },
];

const WINDOWS_SERVER_BUILD_BY_RELEASE: Readonly<Record<string, string>> = {
  "2016": "14393",
  "2019": "17763",
  "2022": "20348",
  "2025": "26100",
};

const COMPONENT_PATTERNS: readonly Readonly<{
  expression: RegExp;
  name: string;
  nodeType: Extract<AttackCentricReusableNodeType, "technology_product" | "security_control">;
  summary: string;
}>[] = [
  {
    expression: /\b(?:custom signed kernel driver|kernel driver with (?:an )?arbitrary callback|\.sys driver with (?:an )?arbitrary callback)\b/iu,
    name: "Custom kernel callback driver",
    nodeType: "technology_product",
    summary: "A custom kernel driver exposed callback or model-specific-register operations; reuse requires an exact private binary fingerprint.",
  },
  {
    expression: /\bsystemd(?: service| unit| drop-in| manager)?\b/iu,
    name: "systemd service manager",
    nodeType: "technology_product",
    summary: "The systemd service manager participated in a reusable privilege-boundary procedure.",
  },
  {
    expression: /\bcron(?:[- ]polled| job| scheduler| directory)?\b/iu,
    name: "Cron scheduler",
    nodeType: "technology_product",
    summary: "A scheduled cron execution boundary participated in a reusable procedure.",
  },
];

const TECHNIQUES: readonly Readonly<{ expression: RegExp; name: string; nodeType: "attack_vector" | "attack_technique" }>[] = [
  { expression: /\bencoded path normalization\b|\bpath normalization (?:bypass|traversal)\b/iu, name: "Encoded path-normalization traversal", nodeType: "attack_vector" },
  { expression: /\bmultipart\b[^\r\n]{0,100}\bfilename\b[^\r\n]{0,100}\btraversal\b|\bfilename traversal\b/iu, name: "Multipart filename traversal", nodeType: "attack_vector" },
  { expression: /\bHarmony Set\b[^\r\n]{0,120}\btype confusion\b|\btype confusion\b[^\r\n]{0,120}\bHarmony Set\b/iu, name: "Harmony Set type confusion", nodeType: "attack_vector" },
  { expression: /\b(?:AAR\s*\/\s*AAW|arbitrary read(?:\s*\/\s*| and )arbitrary write)\b/iu, name: "Arbitrary read/write primitive", nodeType: "attack_technique" },
  { expression: /\bWASM\b[^\r\n]{0,100}\b(?:native|executable|shellcode|code execution)\b/iu, name: "WASM native-code foothold", nodeType: "attack_technique" },
  {
    expression: /\breturn[- ]oriented programming\b|(?:^|[^\p{L}\p{N}])ROP(?:[_-](?:ll|chain))?(?=$|[^\p{L}\p{N}])/iu,
    name: "Return-oriented programming",
    nodeType: "attack_technique",
  },
  { expression: /\b(?:arbitrary )?kernel callback\b|\bIOCTL\b[^\r\n]{0,100}\bcallback\b/iu, name: "Kernel callback invocation", nodeType: "attack_technique" },
  { expression: /\b(?:RDMSR|IA32_LSTAR|live[- ]LSTAR)\b[^\r\n]{0,120}\b(?:KASLR|kernel base)\b|\bKASLR\b[^\r\n]{0,120}\b(?:RDMSR|IA32_LSTAR|live[- ]LSTAR)\b/iu, name: "Live-LSTAR kernel-base discovery", nodeType: "attack_technique" },
  { expression: /\bPTE\b[^\r\n]{0,100}\b(?:U\/S|user\/supervisor|permission)\b|\bpage[- ]table\b[^\r\n]{0,100}\bpermission\b/iu, name: "Page-table permission manipulation", nodeType: "attack_technique" },
  { expression: /\b(?:EPROCESS )?token steal(?:ing)?\b|\btoken replacement\b/iu, name: "Kernel token replacement", nodeType: "attack_technique" },
  { expression: /\bTrapFrame\b[^\r\n]{0,100}\bsysretq?\b|\bswapgs\b[^\r\n]{0,100}\bsysretq?\b/iu, name: "Trap-frame sysret return", nodeType: "attack_technique" },
  { expression: /\bpredictable temp(?:orary)?\b[^\r\n]{0,100}\b(?:pre[- ]?seed|command)\b|\bpre[- ]?seed\b[^\r\n]{0,100}\btemporary command\b/iu, name: "Predictable temporary-command pre-seeding", nodeType: "attack_technique" },
  { expression: /\bPYTHONPATH\b[^\r\n]{0,100}\bsitecustomize(?:\.py)?\b|\bsitecustomize(?:\.py)?\b[^\r\n]{0,100}\bPYTHONPATH\b/iu, name: "Python environment inheritance injection", nodeType: "attack_technique" },
  { expression: /\b(?:spoolss|printer spool)\b[^\r\n]{0,120}\b(?:document[- ]name|job[- ]name|command injection)\b/iu, name: "Printer spool job-name injection", nodeType: "attack_vector" },
  { expression: /\bwide links\b[^\r\n]{0,120}\bforce user\b|\bforce user\b[^\r\n]{0,120}\bwide links\b/iu, name: "Samba symlink-mediated identity write", nodeType: "attack_technique" },
  { expression: /\bwritable\b[^\r\n]{0,100}\bsystemd\b[^\r\n]{0,100}\bdrop[- ]in\b|\bsystemd\b[^\r\n]{0,100}\bdrop[- ]in\b[^\r\n]{0,100}\bwritable\b/iu, name: "Writable service drop-in elevation", nodeType: "attack_technique" },
  { expression: /\bpath traversal\b|\bdirectory traversal\b/iu, name: "Path traversal", nodeType: "attack_vector" },
  { expression: /\bremote code execution\b|\bRCE\b/u, name: "Remote code execution", nodeType: "attack_technique" },
  { expression: /\bcommand injection\b|\bOS command injection\b/iu, name: "Command injection", nodeType: "attack_vector" },
  { expression: /\bSQL injection\b|\bSQLi\b/iu, name: "SQL injection", nodeType: "attack_vector" },
  { expression: /\bserver[- ]side request forgery\b|\bSSRF\b/u, name: "Server-side request forgery", nodeType: "attack_vector" },
  { expression: /\bcross[- ]site scripting\b|\bXSS\b/u, name: "Cross-site scripting", nodeType: "attack_vector" },
  { expression: /\blocal file inclusion\b|\bLFI\b/u, name: "Local file inclusion", nodeType: "attack_vector" },
  { expression: /\bauthentication bypass\b/iu, name: "Authentication bypass", nodeType: "attack_technique" },
  { expression: /\bprivilege escalation\b|\bprivesc\b/iu, name: "Privilege escalation", nodeType: "attack_technique" },
  { expression: /\blateral movement\b/iu, name: "Lateral movement", nodeType: "attack_technique" },
  { expression: /\bNTLM relay\b/iu, name: "NTLM relay", nodeType: "attack_technique" },
  { expression: /\bcredential relay\b/iu, name: "Credential relay", nodeType: "attack_technique" },
  { expression: /\bdeserialization\b/iu, name: "Unsafe deserialization", nodeType: "attack_vector" },
  { expression: /\bserver[- ]side template injection\b|\bSSTI\b/u, name: "Server-side template injection", nodeType: "attack_vector" },
  { expression: /\bXML external entity\b|\bXXE\b/u, name: "XML external entity injection", nodeType: "attack_vector" },
  { expression: /\bLDAP injection\b/iu, name: "LDAP injection", nodeType: "attack_vector" },
  { expression: /\bHTTP request smuggling\b|\brequest smuggling\b/iu, name: "HTTP request smuggling", nodeType: "attack_vector" },
  { expression: /\binsecure direct object reference\b|\bIDOR\b/u, name: "Insecure direct object reference", nodeType: "attack_vector" },
  { expression: /\bunrestricted file upload\b|\barbitrary file upload\b/iu, name: "Unrestricted file upload", nodeType: "attack_vector" },
  { expression: /\barbitrary file read\b/iu, name: "Arbitrary file read", nodeType: "attack_vector" },
  { expression: /\barbitrary file write\b/iu, name: "Arbitrary file write", nodeType: "attack_vector" },
  { expression: /\bprototype pollution\b/iu, name: "Prototype pollution", nodeType: "attack_vector" },
  { expression: /\bJWT (?:algorithm |key )?(?:confusion|bypass)\b/iu, name: "JWT validation bypass", nodeType: "attack_technique" },
  { expression: /\bKerberoast(?:ing)?\b/iu, name: "Kerberoasting", nodeType: "attack_technique" },
  { expression: /\bAS-REP roast(?:ing)?\b/iu, name: "AS-REP roasting", nodeType: "attack_technique" },
  { expression: /\bpassword spray(?:ing)?\b/iu, name: "Password spraying", nodeType: "attack_technique" },
  { expression: /\bDCSync\b/u, name: "DCSync", nodeType: "attack_technique" },
  { expression: /\bADCS (?:abuse|attack)\b|\bcertificate template abuse\b/iu, name: "Active Directory Certificate Services abuse", nodeType: "attack_technique" },
  { expression: /\bcontainer escape\b/iu, name: "Container escape", nodeType: "attack_technique" },
  { expression: /\bbuffer overflow\b/iu, name: "Buffer overflow", nodeType: "attack_vector" },
  { expression: /\bformat string\b/iu, name: "Format-string vulnerability", nodeType: "attack_vector" },
  { expression: /\buse[- ]after[- ]free\b/iu, name: "Use-after-free", nodeType: "attack_vector" },
];

/** These techniques describe an identity or network path, not a property of
 * whichever versioned product happens to be mentioned nearby. They remain
 * reusable concepts, but cannot create a synthetic product-bound procedure. */
const PRODUCT_AGNOSTIC_TECHNIQUES = new Set([
  "Lateral movement",
  "NTLM relay",
  "Credential relay",
  "Kerberoasting",
  "AS-REP roasting",
  "Password spraying",
  "DCSync",
  "Active Directory Certificate Services abuse",
]);

type ScopedPattern = Readonly<{
  all: readonly RegExp[];
  any?: readonly RegExp[];
}>;

type ProcedurePattern = Readonly<{
  match: ScopedPattern;
  name: string;
  summary: string;
}>;

const PROCEDURE_PATTERNS: readonly ProcedurePattern[] = [
  {
    match: {
      all: [
        /--dump-layout\b|\bdump[- ]layout\b/iu,
        /--map\b/iu,
        /--elems\b/iu,
        /(?:^|[^\p{L}\p{N}])rop(?:[_-](?:ll|chain))?(?=$|[^\p{L}\p{N}])/iu,
      ],
    },
    name: "Live-layout refresh before bounded return-oriented execution",
    summary: "Refresh the process-specific memory layout immediately before a bounded return-oriented execution attempt instead of reusing stale layout values.",
  },
  {
    match: { all: [/\bHarmony Set\b|\btype confusion\b/iu, /\b(?:AAR\s*\/\s*AAW|arbitrary read(?:\s*\/\s*| and )arbitrary write)\b/iu, /\bWASM\b/iu] },
    name: "Harmony Set type confusion to WASM native foothold",
    summary: "A type-confusion primitive was developed into arbitrary read/write and then a controlled WASM-backed native execution foothold.",
  },
  {
    match: { all: [/\b(?:arbitrary )?callback\b|\bIOCTL\b/iu, /\b(?:RDMSR|IA32_LSTAR|live[- ]LSTAR)\b/iu, /\b(?:PTE|page[- ]table)\b/iu, /\btoken steal(?:ing)?\b|\btoken replacement\b/iu, /\b(?:TrapFrame|swapgs|sysretq?)\b/iu] },
    name: "Live-LSTAR kernel callback token elevation",
    summary: "A kernel callback and live model-specific-register disclosure were combined with page-table permission changes, token replacement, and a trap-frame return.",
  },
  {
    match: { all: [/\bRDX\b/iu, /\b(?:RDX[- ]relative|lea\s+rsp\s*,\s*\[rdx|return epilogue)\b/iu] },
    name: "RDX-relative kernel return attempt",
    summary: "A kernel return path depended on RDX remaining valid across a call boundary.",
  },
  {
    match: { all: [/\b(?:ASP\.NET|web request|request handler)\b/iu, /\b(?:data\.js|shared input file)\b/iu, /\b(?:d8|external (?:worker|consumer))\b/iu, /\b(?:data\.txt|shared result file)\b/iu] },
    name: "Synchronous shared-file execution request",
    summary: "A web request synchronously delegated execution through shared input and result files to an external worker.",
  },
  {
    match: { all: [/\b(?:encoded path normalization|path normalization)\b/iu, /\b(?:path|directory) traversal\b/iu] },
    name: "Encoded path-normalization traversal",
    summary: "An encoded path was normalized inconsistently and traversed outside the intended application path.",
  },
  {
    match: { all: [/\bmultipart\b/iu, /\bfilename\b/iu, /\b(?:filename|path|directory) traversal\b/iu, /\b(?:cron|scheduled|poll(?:ed|ing)?)\b/iu] },
    name: "Multipart filename traversal to scheduled execution",
    summary: "A multipart filename crossed a storage boundary and placed code where a scheduled process later executed it.",
  },
  {
    match: { all: [/\bneedrestart\b/iu, /\bPYTHONPATH\b/iu, /\bsitecustomize(?:\.py)?\b/iu] },
    name: "Python environment inheritance privilege escalation",
    summary: "A privileged Python process inherited an attacker-controlled module path and loaded a site customization module.",
  },
  {
    match: { all: [/\bpredictable temp(?:orary)?\b|\bcmk_all_/iu, /\b(?:pre[- ]?seed|precreate|pre-create)\b/iu, /\b(?:command|cmd)\b/iu] },
    name: "Predictable temporary-command pre-seeding",
    summary: "A predictable temporary command path was created before a privileged maintenance action consumed it.",
  },
  {
    match: { all: [/\b(?:spoolss|printer spool)\b/iu, /\b(?:document[- ]name|job[- ]name)\b/iu, /\bcommand injection\b/iu] },
    name: "Printer spool job-name command injection",
    summary: "A printer job metadata field crossed into command execution at the print-service boundary.",
  },
  {
    match: { all: [/\bwide links\b/iu, /\bforce user\b/iu, /\b(?:symlink|symbolic link|file write)\b/iu] },
    name: "Samba symlink-mediated identity write",
    summary: "Samba link-following and forced-identity settings enabled a write across an identity or filesystem boundary.",
  },
  {
    match: { all: [/\bsystemd\b/iu, /\bdrop[- ]in\b/iu, /\bwritable\b/iu, /\b(?:SUID|root|privilege escalation)\b/iu] },
    name: "Writable service drop-in privilege escalation",
    summary: "A writable service override was activated through the service manager to cross a local privilege boundary.",
  },
  {
    match: { all: [/\bPHP\b/iu, /\b(?:soft hyphen|0xAD|argument injection|CGI)\b/iu] },
    name: "PHP CGI argument-injection validation",
    summary: "A PHP CGI argument-injection path was evaluated against the exact runtime and configuration fingerprint.",
  },
  {
    match: { all: [/\b(?:ZIP[- ]slip|archive traversal)\b/iu, /\b(?:extract|upload|archive)\b/iu] },
    name: "Archive traversal to execution-path validation",
    summary: "Archive extraction was tested for traversal and separately checked for a reachable execution path.",
  },
];

const TOPOLOGY_PATTERNS: readonly Readonly<{
  match: ScopedPattern;
  name: string;
  summary: string;
  roles: readonly string[];
  attributes?: readonly string[];
}>[] = [
  {
    match: {
      all: [
        /\b(?:ASP\.NET|web request|request handler)\b/iu,
        /\b(?:data\.js|shared input file|producer)\b/iu,
        /\b(?:d8|external (?:worker|consumer)|execution consumer)\b/iu,
        /\b(?:data\.txt|shared result file|result consumer)\b/iu,
      ],
    },
    name: "Synchronous shared-file execution pipeline",
    summary: "A request producer synchronously waits while an external execution consumer exchanges work and results through shared files.",
    roles: ["Request producer", "External execution consumer", "Shared input state", "Shared result state"],
    attributes: ["Shared state lacks per-request correlation", "Shared state lacks mutual exclusion"],
  },
  {
    match: { all: [/\b(?:cron|scheduled)\b/iu, /\b(?:poll|watch)\w*\b/iu, /\b(?:script|file|directory)\b/iu] },
    name: "Scheduled file-consumer execution boundary",
    summary: "A scheduled consumer polls a filesystem location and executes qualifying content across a privilege boundary.",
    roles: ["Filesystem producer", "Scheduled execution consumer"],
  },
  {
    match: { all: [/\b(?:installer repair|MSI repair)\b/iu, /\b(?:different principal|trigger context|SYSTEM)\b/iu] },
    name: "Split-principal maintenance trigger",
    summary: "One security principal prepares reusable state while a different privileged maintenance context consumes it.",
    roles: ["State-preparation principal", "Privileged maintenance trigger"],
  },
];

const TOPOLOGY_ROLES: readonly Readonly<{ expression: RegExp; name: string }>[] = [
  { expression: /\breverse proxy\b/iu, name: "Reverse proxy" },
  { expression: /\bweb application firewall\b|\bWAF\b/u, name: "Web application firewall" },
  { expression: /\bload balancer\b/iu, name: "Load balancer" },
  { expression: /\bapplication server\b/iu, name: "Application server" },
  { expression: /\bdatabase server\b/iu, name: "Database server" },
  { expression: /\bdomain controller\b/iu, name: "Domain controller" },
  { expression: /\bbastion(?: host)?\b|\bjump host\b/iu, name: "Bastion host" },
  { expression: /\bpivot gateway\b|\bpivot host\b/iu, name: "Pivot gateway" },
  { expression: /\bAPI gateway\b/iu, name: "API gateway" },
  { expression: /\bidentity provider\b|\bIdP\b/u, name: "Identity provider" },
  { expression: /\bmessage broker\b/iu, name: "Message broker" },
  { expression: /\bcache server\b/iu, name: "Cache server" },
  { expression: /\bcontainer orchestrator\b/iu, name: "Container orchestrator" },
];

const ATTRIBUTES: readonly Readonly<{ expression: RegExp; name: string }>[] = [
  { expression: /\bdouble[- ](?:URL )?encod(?:e|ed|ing)\b/iu, name: "Double URL encoding" },
  { expression: /\bURL encod(?:e|ed|ing)\b/iu, name: "URL encoding" },
  { expression: /\bnull byte\b/iu, name: "Null-byte terminator" },
  { expression: /\bchunked transfer encoding\b/iu, name: "Chunked transfer encoding" },
  { expression: /\bHTTP (?:GET|POST|PUT|PATCH|DELETE)\b/iu, name: "Explicit HTTP method" },
  { expression: /\bcase normalization\b|\bcase[- ]sensitive bypass\b/iu, name: "Case normalization variance" },
  { expression: /\bMETHOD_NEITHER\b|\braw (?:user )?pointers?\b/iu, name: "Raw user-pointer IOCTL contract" },
  { expression: /\b(?:arbitrary )?callback\b/iu, name: "Arbitrary callback primitive" },
  { expression: /\b(?:RDMSR|READ_MSR)\b/iu, name: "Model-specific-register read primitive" },
  { expression: /\bone[- ]shot\b|\bzero retr(?:y|ies)\b/iu, name: "One-shot execution policy" },
  { expression: /\bno request ID\b|\bwithout (?:a )?request ID\b/iu, name: "No per-request correlation" },
  { expression: /\bno (?:file )?lock\b|\bwithout (?:a )?lock\b/iu, name: "No shared-state locking" },
  { expression: /\bstale (?:previous )?(?:result|data\.txt|output)\b/iu, name: "Stale shared result can satisfy a fresh request" },
  { expression: /\bMSI\b[^\r\n]{0,100}\b(?:1603|exit code)\b[^\r\n]{0,100}\b(?:payload|execution)\b/iu, name: "Process exit code is not authoritative attack evidence" },
];

const FAILURE_ATTRIBUTES: readonly Readonly<{ expression: RegExp; name: string }>[] = [
  { expression: /\b(?:KeSetPriorityThread[^\r\n]{0,100})?clobber(?:ed|s|ing)?\s+RDX\b|\bRDX\b[^\r\n]{0,100}\bclobber(?:ed|s|ing)?\b/iu, name: "RDX was clobbered across the kernel call" },
  { expression: /\b(?:invalid|unsafe)\b[^\r\n]{0,80}\bRDX[- ]relative return\b|\blea\s+rsp\s*,\s*\[rdx[^\]]*\]/iu, name: "RDX-relative return state was invalid" },
  { expression: /\bSMAP[- ]unsafe\b|\buser metadata\b[^\r\n]{0,100}\bSMAP\b/iu, name: "User metadata was unsafe under SMAP" },
  { expression: /\b(?:hard|boot)[- ]pinned\b[^\r\n]{0,80}\bLSTAR\b|\bhard[- ]coded LSTAR\b/iu, name: "Boot-specific LSTAR value was reused" },
  { expression: /\bstale (?:previous )?(?:result|data\.txt|output)\b[^\r\n]{0,120}\b(?:false|fast|accepted|returned)\b/iu, name: "Stale shared result masked the in-flight attempt" },
  { expression: /\b(?:blacklist(?:ed)?|blocked)\b[^\r\n]{0,100}\b(?:path|directory)\b|\b(?:path|directory)\b[^\r\n]{0,100}\bblacklist(?:ed)?\b/iu, name: "Selected execution path was excluded by policy" },
  { expression: /\bpython(?:3)?\s+-c\b[^\r\n]{0,100}\b(?:skip|ignored|did not)\b|\b(?:skip|ignored)\b[^\r\n]{0,100}\bpython(?:3)?\s+-c\b/iu, name: "Inline Python invocation was not inspected" },
  { expression: /\b(?:wrong|different|required|alternate)\b[^\r\n]{0,100}\b(?:principal|trigger context)\b|\btrigger context\b[^\r\n]{0,100}\b(?:mismatch|failed|required)\b/iu, name: "Maintenance trigger context did not satisfy the prerequisite" },
];

const PREREQUISITES: readonly Readonly<{ expression: RegExp; name: string }>[] = [
  { expression: /\bexact version (?:match|required|confirmed)\b/iu, name: "Exact product version is confirmed" },
  { expression: /\bauthenticated session\b/iu, name: "An authenticated session is available" },
  { expression: /\blow[- ]privilege (?:shell|session|user)\b/iu, name: "A low-privilege execution context is available" },
  { expression: /\bwritable (?:directory|path|file)\b/iu, name: "The required storage location is writable" },
  { expression: /\bclean boot\b/iu, name: "The system is at a verified clean boot" },
  { expression: /\bmodule (?:is )?enabled\b|\brequired module\b/iu, name: "The required application module is enabled" },
];

const DISCOVERY_PATTERNS: readonly Readonly<{ expression: RegExp; name: string; summary: string }>[] = [
  { expression: /\bserver header\b|\bServer:\s*[^\r\n]+/iu, name: "HTTP server-header fingerprint", summary: "A product or version was inferred from an HTTP server header and remains banner-derived until corroborated." },
  { expression: /\bNmap\b|\bservice scan\b/iu, name: "Active service fingerprint", summary: "A product or version was reported by an active service-fingerprinting scan." },
  { expression: /\bTLS certificate\b|\bssl-cert\b/iu, name: "TLS certificate fingerprint", summary: "Certificate metadata contributed to technology or topology identification." },
  { expression: /\bkernel version\b|\buname\b/iu, name: "Kernel build fingerprint", summary: "Kernel build information was observed and should be matched exactly before procedure reuse." },
  { expression: /\bCPE:/iu, name: "CPE fingerprint", summary: "A CPE-formatted product fingerprint was reported and requires applicability validation." },
  { expression: /\bHTTP title\b|\bhttp-title\b/iu, name: "HTTP title fingerprint", summary: "An HTTP page title contributed a low-confidence application fingerprint." },
];

const FAILURE_MODES: readonly Readonly<{ expression: RegExp; name: string; symptom: string; causeCategory?: string }>[] = [
  { expression: /\bhang(?:s|ing|ed)?\b|\bwedged\b|\bstuck\b/iu, name: "Application or system hang", symptom: "The affected execution path stopped producing a trustworthy terminal result." },
  { expression: /\btime(?:d)? out\b|\btimeout\b/iu, name: "Execution timeout", symptom: "The operation exceeded its bounded completion window." },
  { expression: /\bcrash(?:ed|es|ing)?\b|\bsegmentation fault\b/iu, name: "Process or system crash", symptom: "The affected process or system terminated unexpectedly." },
  { expression: /\bservice (?:became )?unreachable\b|\bconnection refused\b/iu, name: "Service became unavailable", symptom: "The affected service stopped accepting expected connections." },
  { expression: /\blockout\b|\baccount locked\b/iu, name: "Authentication lockout", symptom: "Authentication attempts caused an account or service lockout." },
  { expression: /\b(?:KeSetPriorityThread[^\r\n]{0,100})?clobber(?:ed|s|ing)?\s+RDX\b|\bRDX[- ]relative return\b[^\r\n]{0,100}\b(?:invalid|failed|hung)\b/iu, name: "Kernel return-register corruption", symptom: "The return path depended on a register that a preceding kernel call was allowed to overwrite.", causeCategory: "calling_convention_state" },
  { expression: /\bSMAP[- ]unsafe\b|\buser metadata\b[^\r\n]{0,100}\bSMAP\b/iu, name: "SMAP-unsafe user-memory dependency", symptom: "The kernel procedure depended on user-space metadata that was not safe under supervisor-mode access prevention.", causeCategory: "memory_protection" },
  { expression: /\b(?:hard|boot)[- ]pinned\b[^\r\n]{0,80}\bLSTAR\b|\bhard[- ]coded LSTAR\b/iu, name: "Stale boot-specific kernel address", symptom: "A boot-specific kernel address was reused instead of being derived from the live system state.", causeCategory: "stale_runtime_address" },
  { expression: /\bstale (?:previous )?(?:result|data\.txt|output)\b[^\r\n]{0,120}\b(?:false|fast|accepted|returned)\b/iu, name: "Stale shared-result race", symptom: "A shared result from an earlier request was accepted as if it belonged to the current request.", causeCategory: "shared_state_race" },
  { expression: /\b(?:blacklist(?:ed)?|blocked)\b[^\r\n]{0,100}\b(?:path|directory)\b|\bpython(?:3)?\s+-c\b[^\r\n]{0,100}\b(?:skip|ignored|did not)\b/iu, name: "Execution trigger excluded the selected input", symptom: "The selected path or invocation form did not enter the privileged trigger's inspected execution path.", causeCategory: "trigger_filter" },
  { expression: /\btrigger context\b[^\r\n]{0,100}\b(?:mismatch|failed|required|wrong principal)\b|\b(?:different|required|alternate|wrong) principal\b[^\r\n]{0,100}\b(?:trigger|repair)\b/iu, name: "Maintenance trigger-context mismatch", symptom: "The maintenance action was invoked from a principal or context that could not activate the privileged consumer.", causeCategory: "execution_context" },
];

const RECOVERY_PATTERNS: readonly Readonly<{ expression: RegExp; name: string; summary: string }>[] = [
  { expression: /\b(?:reset|reboot)(?:ed|ing)?\b/iu, name: "Disposable environment reset", summary: "Restore a clean disposable environment before considering another bounded attempt." },
  { expression: /\brecycle(?:d|s|ing)?\b.*\b(?:application pool|worker|service)\b|\bapplication pool\b.*\brecycle/iu, name: "Application worker recycle", summary: "Recycle only the affected application worker, then prove the execution path is healthy." },
  { expression: /\brestart(?:ed|ing)?\b.*\bservice\b|\bservice\b.*\brestart/iu, name: "Service restart and verification", summary: "Restart the affected service and require an execution-path health check before retry." },
  { expression: /\bwait\b[^\r\n]{0,100}\b(?:past|beyond|longer than)\b[^\r\n]{0,80}\b(?:execution )?timeout\b|\bdrain\b[^\r\n]{0,80}\b(?:timeout|in[- ]flight)\b/iu, name: "Execution-timeout drain", summary: "Wait beyond the bounded execution timeout so unresolved work can drain before testing recovery or considering another attempt." },
  { expression: /\b(?:never|do not|must not)\b[^\r\n]{0,100}\b(?:refire|re-fire|rerun|repeat)\b[^\r\n]{0,100}\b(?:retired|one[- ]shot|unresolved|package|procedure)\b/iu, name: "Retire the unresolved one-shot procedure", summary: "Do not refire an unresolved or retired one-shot procedure; use a reviewed alternative only after the execution path is healthy." },
];

const HEALTH_CHECKS: readonly Readonly<{ expression: RegExp; name: string; summary: string }>[] = [
  { expression: /\bhealth (?:check|probe|gate)\b/iu, name: "Affected execution-path health check", summary: "Prove that the affected execution path completes a harmless bounded operation before retry." },
  { expression: /\bbase page (?:loads|responds|reachable)\b.*\b(?:not enough|insufficient|but)\b/iu, name: "Base-page liveness is insufficient", summary: "A reachable base page does not prove that the affected application execution path recovered." },
  { expression: /\bharmless (?:scalar|expression|execution) (?:check|probe)\b/iu, name: "Harmless execution probe", summary: "Require a fresh harmless execution probe with a terminal result before retry." },
  { expression: /\bno (?:prior|previous) (?:process|request|attempt).*(?:remain|in flight|running)\b/iu, name: "No prior attempt remains in flight", summary: "Confirm that no prior attempt remains unresolved before another execution." },
  { expression: /\b(?:HTTP\s+)?GET\b[^\r\n]{0,120}\b(?:works|loads|returns|200|OK)\b[^\r\n]{0,160}\b(?:not enough|insufficient|does not prove|bypasses)\b|\bGET liveness\b[^\r\n]{0,100}\b(?:not enough|insufficient)\b/iu, name: "HTTP GET liveness is insufficient", summary: "A successful GET can bypass the affected execution worker and therefore does not prove that the execution path recovered." },
  { expression: /\b(?:harmless\s+)?POST\b[^\r\n]{0,160}\b(?:print\s*\(\s*1\s*\)|scalar|execution (?:check|probe))\b|\bprint\s*\(\s*1\s*\)\b[^\r\n]{0,160}\bPOST\b/iu, name: "Harmless POST execution probe", summary: "Submit a fresh harmless POST that must return the expected scalar result, proving the affected execution worker rather than only the web front end." },
];

const MISCONFIGURATION_PATTERNS: readonly Readonly<{ expression: RegExp; name: string; summary: string }>[] = [
  {
    expression: /\bunauthenticated\b[^\r\n]{0,120}\b(?:JavaScript|d8|code|expression)\b[^\r\n]{0,80}\b(?:evaluat|execut)/iu,
    name: "Unauthenticated server-side expression evaluation",
    summary: "An unauthenticated input crossed into a server-side expression or code-evaluation boundary.",
  },
  {
    expression: /\bno request ID\b|\bwithout (?:a )?request ID\b|\bno (?:file )?lock\b|\bwithout (?:a )?lock\b/iu,
    name: "Uncorrelated unlocked shared execution state",
    summary: "Shared execution files lacked request correlation or mutual exclusion, allowing stale results and overlapping work.",
  },
  {
    expression: /\bwide links\s*=\s*yes\b[^\r\n]{0,160}\bforce user\b|\bforce user\b[^\r\n]{0,160}\bwide links\s*=\s*yes\b/iu,
    name: "Insecure Samba link-following identity boundary",
    summary: "Link-following and forced-user settings combined to permit writes through a different filesystem identity.",
  },
];

function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function fact(
  nodeType: AttackCentricReusableNodeType,
  title: string,
  summary: string,
  body: unknown,
  confidence: number,
): Fact {
  return { nodeType, title, summary, body: canonicalJson(body), confidence };
}

function reset(expression: RegExp): void { expression.lastIndex = 0; }

function matched(expression: RegExp, text: string): boolean {
  reset(expression);
  return expression.test(text);
}

function matchedScopedPattern(pattern: ScopedPattern, text: string): boolean {
  return pattern.all.every((expression) => matched(expression, text)) &&
    (!pattern.any || pattern.any.some((expression) => matched(expression, text)));
}

type ProductMatch = Readonly<{
  name: string;
  version: string;
  nodeType: ProductPattern["nodeType"];
}>;

function reusableVersionFingerprint(value: string): string | undefined {
  const components = value.split(".");
  const looksLikeIpv4 = components.length === 4 && components.every((component) => {
    if (!/^\d{1,3}$/u.test(component)) return false;
    const numeric = Number(component);
    return numeric >= 0 && numeric <= 255;
  });
  // A dotted-quad made only from valid IPv4 octets is indistinguishable from
  // an address after operational context is removed. Never relabel it as a
  // software build: a false negative is safer than reusable target leakage.
  return looksLikeIpv4 ? undefined : value;
}

function productVersionIsConsistent(product: ProductPattern, version: string): boolean {
  if (product.name !== "Windows Server") return true;
  const observation = /^(20\d{2})(?:\s+(?:Build|revision)\s+(\d+)(?:\.\d+)*)?$/iu.exec(version);
  if (!observation) return false;
  const [, release, build] = observation;
  if (!build) return true;
  const expectedBuild = WINDOWS_SERVER_BUILD_BY_RELEASE[release!];
  // A build-bearing observation is admitted only when the release/build pair
  // is one we can validate deterministically. Year-only observations remain.
  return expectedBuild !== undefined && build === expectedBuild;
}

function collectProducts(text: string): readonly ProductMatch[] {
  const products = new Map<string, ProductMatch>();
  for (const pattern of PRODUCT_PATTERNS) {
    reset(pattern.expression);
    for (const match of text.matchAll(pattern.expression)) {
      const rawVersion = match[1]?.replace(/\s+/gu, " ").trim();
      const version = rawVersion ? reusableVersionFingerprint(rawVersion) : undefined;
      if (!version || version.length > 80 || !productVersionIsConsistent(pattern, version)) continue;
      const item = { name: pattern.name, version, nodeType: pattern.nodeType };
      products.set(`${item.nodeType}\0${item.name}\0${item.version}`, item);
    }
  }
  return [...products.values()].sort((left, right) =>
    left.name.localeCompare(right.name) || left.version.localeCompare(right.version));
}

/** Markdown headings are context, not a license to merge all content below
 * them. Each paragraph, list item, or fenced block becomes an independent
 * scope with its nearest heading retained. Outcome and technique language can
 * therefore never cross a neighbouring block merely because both appeared in
 * one large report section. */
function semanticScopes(text: string, markdownHeadings = true): readonly string[] {
  const normalized = text.replace(/\r\n?/gu, "\n");
  const lines = normalized.split("\n");
  const hasHeadings = markdownHeadings && lines.some((line) => /^\s{0,3}#{1,6}\s+\S/u.test(line));
  if (!hasHeadings) {
    const blocks = markdownHeadings
      ? markdownSectionBlocks(normalized)
      : normalized.split(/\n\s*\n/gu).map((value) => value.trim()).filter(Boolean);
    return blocks.length > 0 ? blocks : [normalized];
  }
  const scopes: string[] = [];
  let heading: string | undefined;
  let body: string[] = [];
  const flush = (): void => {
    const blocks = markdownSectionBlocks(body.join("\n"));
    if (blocks.length === 0) {
      if (heading) scopes.push(heading);
    } else {
      blocks.forEach((block) => scopes.push(heading ? `${heading}\n\n${block}` : block));
    }
    body = [];
  };
  for (const line of lines) {
    if (/^\s{0,3}#{1,6}\s+\S/u.test(line)) {
      if (heading || body.some((value) => value.trim())) flush();
      heading = line.trim();
      continue;
    }
    body.push(line);
  }
  if (heading || body.some((value) => value.trim())) flush();
  return scopes.filter(Boolean);
}

type ReusableSourceSegment = Readonly<{
  ordinal: number;
  text: string;
  contentHash: string;
  /** False preserves the historical whole-file receipt identity. */
  isolatedFromMixedSource: boolean;
}>;

type ReusableSourcePartition = Readonly<{
  safeSegments: readonly ReusableSourceSegment[];
  secretBearingSegmentsQuarantined: number;
}>;

function containsReusableMemorySecret(value: string): boolean {
  return containsHardSecret(value) || findReusableMemorySecretCategories(value).length > 0;
}

/**
 * Break a Markdown section into independently meaningful blocks. Fenced code
 * is atomic and each top-level list item is independent, which matches the
 * shape of NEXT_ACTIONS and council notes without allowing a secret-bearing
 * item to contaminate or bless a neighbouring item.
 */
function markdownSectionBlocks(body: string): readonly string[] {
  const blocks: string[] = [];
  let current: string[] = [];
  let fence: "```" | "~~~" | undefined;
  const flush = (): void => {
    const value = current.join("\n").trim();
    if (value) blocks.push(value);
    current = [];
  };

  for (const line of body.replace(/\r\n?/gu, "\n").split("\n")) {
    const fenceMatch = /^\s{0,3}(```|~~~)/u.exec(line)?.[1] as "```" | "~~~" | undefined;
    if (fence) {
      current.push(line);
      if (fenceMatch === fence) {
        fence = undefined;
        flush();
      }
      continue;
    }
    if (fenceMatch) {
      flush();
      current.push(line);
      fence = fenceMatch;
      continue;
    }
    if (!line.trim()) {
      flush();
      continue;
    }
    if (/^\s{0,3}(?:[-*+]|\d+[.)])\s+\S/u.test(line)) flush();
    current.push(line);
  }
  flush();
  return blocks;
}

/**
 * Whole safe files retain their previous receipt identity. A mixed Markdown
 * file is instead represented by independently checked safe blocks. Unsafe
 * bytes remain only in the protected private source and are never returned,
 * logged, or passed to the reusable-memory extractor.
 */
function reusableSourcePartition(text: string, extension: string): ReusableSourcePartition {
  if (!containsReusableMemorySecret(text)) {
    return {
      safeSegments: [{ ordinal: 0, text, contentHash: sha256(text), isolatedFromMixedSource: false }],
      secretBearingSegmentsQuarantined: 0,
    };
  }
  // Structured documents and executable scripts are semantically coupled;
  // partial extraction would make their meaning ambiguous. Keep them fail-closed.
  if (extension !== ".md") return { safeSegments: [], secretBearingSegmentsQuarantined: 1 };

  const safe: ReusableSourceSegment[] = [];
  let quarantined = 0;
  let ordinal = 0;
  for (const section of semanticScopes(text, true)) {
    if (!containsReusableMemorySecret(section)) {
      safe.push({
        ordinal,
        text: section,
        contentHash: sha256(section),
        isolatedFromMixedSource: true,
      });
      ordinal += 1;
      continue;
    }

    const lines = section.replace(/\r\n?/gu, "\n").split("\n");
    const heading = /^\s{0,3}#{1,6}\s+\S/u.test(lines[0] ?? "") ? lines.shift()!.trim() : undefined;
    // A secret in a heading is inherited by every child block, so the entire
    // section must remain private rather than reusing the heading as context.
    if (heading && containsReusableMemorySecret(heading)) {
      quarantined += 1;
      ordinal += 1;
      continue;
    }
    const blocks = markdownSectionBlocks(lines.join("\n"));
    if (blocks.length === 0) {
      quarantined += 1;
      ordinal += 1;
      continue;
    }
    for (const block of blocks) {
      const candidate = heading ? `${heading}\n\n${block}` : block;
      if (containsReusableMemorySecret(candidate)) {
        quarantined += 1;
        ordinal += 1;
        continue;
      }
      safe.push({
        ordinal,
        text: candidate,
        contentHash: sha256(candidate),
        isolatedFromMixedSource: true,
      });
      ordinal += 1;
    }
  }
  return { safeSegments: safe, secretBearingSegmentsQuarantined: quarantined };
}

/**
 * Discovery correctly quarantines a mixed secret-bearing file from canonical
 * legacy import. Attack-knowledge-only extraction may still inspect a pinned
 * Markdown reference and retain only the independently safe blocks above.
 * Other quarantine categories, formats, and incomplete source identities stay
 * excluded. This does not make the source itself canonical or reusable.
 */
function reusableMarkdownQuarantineReferences(
  manifest: LegacyEngagementManifest,
): readonly LegacyEngagementFile[] {
  const references: LegacyEngagementFile[] = [];
  for (const item of manifest.quarantined) {
    if (item.category !== "sensitive_content" || item.sourceKind !== "regular_file" ||
        item.sourceSha256 === undefined || item.byteSize === undefined || item.modifiedAt === undefined ||
        extname(item.absolutePath).toLowerCase() !== ".md") continue;
    const relativePath = relative(manifest.engagementDirectory, item.absolutePath).replaceAll("\\", "/");
    if (!relativePath || relativePath === ".." || relativePath.startsWith("../") || relativePath.startsWith("/")) continue;
    references.push({
      absolutePath: item.absolutePath,
      relativePath,
      kind: "note",
      contentClass: "text",
      mediaType: "text/markdown",
      sha256: item.sourceSha256,
      byteSize: item.byteSize,
      modifiedAt: item.modifiedAt,
    });
  }
  return references.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
}

function procedureAssociationKey(name: string): string {
  return `procedure:${sha256(name.toLowerCase()).slice(0, 24)}`;
}

function genericAssociationKey(technique: string, product: ProductMatch): string {
  return `generic:${sha256(canonicalJson({ technique, product: product.name, version: product.version })).slice(0, 24)}`;
}

function preferredScopedProduct(products: readonly ProductMatch[]): ProductMatch | undefined {
  const ranks: readonly ProductPattern["nodeType"][][] = [
    ["technology_product"],
    ["framework", "runtime"],
    ["kernel", "operating_system"],
    ["database", "firewall", "waf", "proxy", "security_control"],
  ];
  for (const rank of ranks) {
    const matches = products.filter((product) => rank.includes(product.nodeType));
    if (matches.length === 1) return matches[0];
    if (matches.length > 1) return undefined;
  }
  return undefined;
}

function associationKey(item: Fact): string | undefined {
  const value = parsedBody(item).associationKey;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function topologyKey(item: Fact): string | undefined {
  const value = parsedBody(item).topologyKey;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function safeScriptLanguage(extension: string): string {
  return ({
    ".py": "Python", ".sh": "Shell", ".ps1": "PowerShell", ".js": "JavaScript",
    ".ts": "TypeScript", ".rb": "Ruby", ".go": "Go", ".c": "C", ".cpp": "C++",
  } as Record<string, string>)[extension] ?? "Text";
}

function normalizedExecutionAttributes(text: string): Readonly<Record<string, string | number | boolean>> {
  const attributes: Record<string, string | number | boolean> = {};
  const boundedNumber = (expression: RegExp, key: string, minimum: number, maximum: number): void => {
    reset(expression);
    const raw = expression.exec(text)?.[1];
    const value = raw === undefined ? NaN : Number(raw);
    if (Number.isSafeInteger(value) && value >= minimum && value <= maximum) attributes[key] = value;
  };
  boundedNumber(/(?:--?(?:threads?|workers?|concurrency)|\bconcurrency\b)\s*(?:=|:|\s)\s*(\d{1,5})\b/iu, "concurrency", 1, 10_000);
  boundedNumber(/(?:--?timeout|\btimeout\b)\s*(?:=|:|\s)\s*(\d{1,8})\b/iu, "timeout", 0, 86_400_000);
  boundedNumber(/(?:--?retries|\bretr(?:y|ies)\b)\s*(?:=|:|\s)\s*(\d{1,5})\b/iu, "retries", 0, 10_000);
  const method = /\b(?:method\s*[:=]\s*|HTTP\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/iu.exec(text)?.[1];
  if (method) attributes.httpMethod = method.toUpperCase();
  if (/\bdouble[- ](?:URL )?encod/iu.test(text)) attributes.doubleUrlEncoding = true;
  if (/\bautomatic retr(?:y|ies)\b.*\b(?:disabled|zero|none)\b/iu.test(text)) attributes.automaticRetries = 0;
  return Object.fromEntries(Object.entries(attributes).sort(([left], [right]) => left.localeCompare(right)));
}

interface Extraction {
  readonly facts: readonly RoleFact[];
  readonly edges: readonly ReusableAttackBundleKnowledge["edges"][number][];
  readonly ambiguousFragments: number;
}

interface RoleFact extends Fact { readonly role: string }

function parsedBody(item: Fact): Record<string, unknown> {
  try {
    const value = JSON.parse(item.body) as unknown;
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch { return {}; }
}

/** Build only relationships whose two endpoints are unambiguous within this
 * exact hash-verified source. No relationship is inferred across files. */
function connectedFacts(facts: readonly Fact[]): {
  readonly facts: readonly RoleFact[];
  readonly edges: readonly ReusableAttackBundleKnowledge["edges"][number][];
} {
  const counters = new Map<string, number>();
  const roleFacts: RoleFact[] = facts.map((item) => {
    const count = counters.get(item.nodeType) ?? 0;
    counters.set(item.nodeType, count + 1);
    // `target_*` is reserved for canonical operational record identifiers at
    // the reusable-memory boundary. Use a semantic local bundle role instead.
    const rolePrefix = item.nodeType === "target_state_transition" ? "state_transition" : item.nodeType;
    return { ...item, role: `${rolePrefix}.${count}` };
  });
  const byType = (nodeType: AttackCentricReusableNodeType): readonly RoleFact[] =>
    roleFacts.filter((item) => item.nodeType === nodeType);
  const edgeMap = new Map<string, ReusableAttackBundleKnowledge["edges"][number]>();
  const add = (source: RoleFact | undefined, edgeType: ReusableAttackBundleKnowledge["edges"][number]["edgeType"], target: RoleFact | undefined): void => {
    if (!source || !target) return;
    const edge = { sourceRole: source.role, edgeType, targetRole: target.role };
    edgeMap.set(canonicalJson(edge), edge);
  };
  const productTypes: readonly AttackCentricReusableNodeType[] = [
    "technology_product", "operating_system", "kernel", "framework", "runtime",
    "database", "firewall", "waf", "proxy", "security_control",
  ];
  const products = roleFacts.filter((item) => productTypes.includes(item.nodeType));
  const versions = byType("exact_version_fingerprint");
  const versionRanges = byType("version_range_fingerprint");
  for (const product of products) {
    const productVersion = String(parsedBody(product).exactVersion ?? "");
    const matching = versions.filter((version) => {
      const body = parsedBody(version);
      return body.product === product.title && body.exactVersion === productVersion;
    });
    if (matching.length === 1) add(product, "has_exact_version", matching[0]);
    const matchingRanges = versionRanges.filter((range) => parsedBody(range).product === product.title);
    matchingRanges.forEach((range) => add(product, "has_version_range", range));
    if (matching.length === 1 && matchingRanges.length === 1) {
      add(matching[0], "version_in_range", matchingRanges[0]);
    }
  }
  // Generic execution components such as cron or systemd are useful graph
  // nodes, but they are not a version-bound application identity. Treating
  // whichever generic component happened to be the only technology_product
  // in a source as the "primary" product fabricated relationships such as a
  // CVE affecting Cron merely because both strings occurred in one file.
  // Product-bound relationships require an exact fingerprint emitted by the
  // product registry.
  const concreteProducts = products.filter((item) => {
    const exactVersion = parsedBody(item).exactVersion;
    return typeof exactVersion === "string" && exactVersion.trim().length > 0;
  });
  const primaryProducts = byType("technology_product").filter((item) =>
    concreteProducts.includes(item));
  const primary = primaryProducts.length === 1 ? primaryProducts[0] : undefined;
  if (primary) {
    byType("operating_system").forEach((item) => add(primary, "runs_on", item));
    byType("kernel").forEach((item) => add(primary, "runs_on", item));
    byType("framework").forEach((item) => add(primary, "built_with", item));
    byType("runtime").forEach((item) => add(primary, "uses_runtime", item));
    byType("database").forEach((item) => add(primary, "uses_database", item));
    [...byType("firewall"), ...byType("waf"), ...byType("proxy"), ...byType("security_control")]
      .forEach((item) => add(primary, "protected_by", item));
    byType("discovery_pattern").forEach((item) => add(primary, "discovered_by", item));
    for (const weakness of [...byType("cve"), ...byType("advisory"), ...byType("misconfiguration")]) {
      add(weakness, "affects", primary);
      const exact = versions.filter((version) => parsedBody(version).product === primary.title);
      if (exact.length === 1) add(weakness, "affects", exact[0]);
    }
  }
  for (const attack of [...byType("attack_vector"), ...byType("attack_technique")]) {
    const bindings = parsedBody(attack).products;
    if (!Array.isArray(bindings)) continue;
    for (const value of bindings) {
      if (!value || typeof value !== "object") continue;
      const binding = value as { name?: unknown; exactVersion?: unknown };
      if (typeof binding.name !== "string" || typeof binding.exactVersion !== "string") continue;
      const scopedProduct = products.find((item) =>
        item.title === binding.name && parsedBody(item).exactVersion === binding.exactVersion);
      add(attack, "applicable_to", scopedProduct);
    }
  }
  const cves = byType("cve");
  const cwes = byType("cwe");
  if (cves.length === 1 && cwes.length === 1) add(cves[0], "classified_as", cwes[0]);
  const procedures = byType("attack_procedure");
  const scripts = byType("script_artifact");
  const associatedWith = (procedure: RoleFact, items: readonly RoleFact[]): readonly RoleFact[] => {
    const key = associationKey(procedure);
    if (key) return items.filter((item) => associationKey(item) === key);
    return procedures.length === 1 ? items.filter((item) => !associationKey(item)) : [];
  };
  for (const procedure of procedures) {
    const body = parsedBody(procedure);
    const explicitAttackConcepts = Array.isArray(body.attackConcepts)
      ? body.attackConcepts.filter((value): value is { name: string; nodeType: "attack_vector" | "attack_technique" } =>
        Boolean(value) && typeof value === "object" &&
        typeof (value as { name?: unknown }).name === "string" &&
        ["attack_vector", "attack_technique"].includes(
          String((value as { nodeType?: unknown }).nodeType),
        ))
      : [];
    for (const concept of explicitAttackConcepts) {
      const matches = roleFacts.filter((item) =>
        item.nodeType === concept.nodeType && item.title === concept.name);
      // The extractor records a classification only when one exact concept
      // endpoint exists in this hash-bound bundle. Duplicate or absent roles
      // fail closed instead of being guessed from source-wide co-occurrence.
      if (matches.length === 1) add(procedure, "classified_as", matches[0]);
    }
    const productBindings = Array.isArray(body.products)
      ? body.products.filter((value): value is { name: string; exactVersion: string } =>
        Boolean(value) && typeof value === "object" &&
        typeof (value as { name?: unknown }).name === "string" &&
        typeof (value as { exactVersion?: unknown }).exactVersion === "string")
      : [];
    if (productBindings.length > 0) {
      for (const binding of productBindings) {
        const product = products.find((item) => item.title === binding.name && parsedBody(item).exactVersion === binding.exactVersion);
        add(procedure, "tested_against", product);
        const exact = versions.find((item) => parsedBody(item).product === binding.name && parsedBody(item).exactVersion === binding.exactVersion);
        add(procedure, "tested_against", exact);
      }
    } else {
      add(procedure, "tested_against", primary);
      if (primary) {
        const exact = versions.filter((version) => parsedBody(version).product === primary.title);
        if (exact.length === 1) add(procedure, "tested_against", exact[0]);
      }
    }
    if (scripts.length === 1 && (procedures.length === 1 || parsedBody(procedure).scriptContentHash === parsedBody(scripts[0]!).contentHash)) {
      add(procedure, "implemented_by", scripts[0]);
    }
    associatedWith(procedure, byType("prerequisite")).forEach((item) => add(procedure, "requires", item));
    associatedWith(procedure, byType("attribute")).forEach((item) => add(procedure, "has_attribute", item));
    const scopedCves = Array.isArray(body.cves) ? new Set(body.cves.filter((value): value is string => typeof value === "string")) : undefined;
    const applicableCves = scopedCves ? cves.filter((item) => scopedCves.has(item.title)) : (cves.length === 1 ? cves : []);
    applicableCves.forEach((item) => add(procedure, "exploits", item));
    const scopedWeaknesses = associatedWith(procedure, byType("misconfiguration"));
    scopedWeaknesses.forEach((item) => add(procedure, "exploits", item));
    associatedWith(procedure, byType("outcome")).forEach((item) => add(procedure, "produces_outcome", item));
    associatedWith(procedure, byType("operational_hazard")).forEach((item) => {
      add(procedure, "caused", item);
      add(procedure, "avoid_after", item);
    });
    associatedWith(procedure, byType("health_check")).forEach((item) => add(procedure, "safe_when", item));
  }
  if (scripts.length === 1) {
    // A script that names one exact product/runtime is explicitly bound to
    // that fingerprint even when the product is not a top-level application
    // (for example, an offline decoder for one V8 build). Multiple products
    // remain ambiguous and deliberately produce no relationship.
    const soleScriptProduct = concreteProducts.length === 1 ? concreteProducts[0] : primary;
    add(scripts[0], "tested_against", soleScriptProduct);
    if (soleScriptProduct) {
      const exact = versions.filter((version) => {
        const body = parsedBody(version);
        return body.product === soleScriptProduct.title &&
          body.exactVersion === parsedBody(soleScriptProduct).exactVersion;
      });
      if (exact.length === 1) add(scripts[0], "tested_against", exact[0]);
    }
    byType("outcome").forEach((item) => add(scripts[0], "produces_outcome", item));
  }
  const failedOutcomes = byType("outcome").filter(
    (item) => parsedBody(item).reportedStatus === "failed",
  );
  const failureModes = byType("failure_mode");
  for (const outcome of failedOutcomes) {
    const key = associationKey(outcome);
    const matching = key
      ? failureModes.filter((item) => associationKey(item) === key)
      : (failedOutcomes.length === 1 ? failureModes.filter((item) => !associationKey(item)) : []);
    matching.forEach((item) => add(outcome, "failed_because", item));
  }
  const recoveries = byType("recovery_pattern");
  failureModes.forEach((failure) => {
    const key = associationKey(failure);
    const matching = key
      ? recoveries.filter((item) => associationKey(item) === key)
      : (failureModes.length === 1 ? recoveries.filter((item) => !associationKey(item)) : []);
    matching.forEach((recovery) => add(failure, "recovered_with", recovery));
  });
  for (const hazard of byType("operational_hazard")) {
    const key = associationKey(hazard);
    const matchingRecoveries = key
      ? recoveries.filter((item) => associationKey(item) === key)
      : recoveries.filter((item) => !associationKey(item));
    matchingRecoveries.forEach((recovery) => {
      add(hazard, "requires_recovery", recovery);
      add(hazard, "mitigated_by", recovery);
    });
    const matchingHealth = key
      ? byType("health_check").filter((item) => associationKey(item) === key)
      : byType("health_check").filter((item) => !associationKey(item));
    matchingHealth.forEach((health) => {
      add(hazard, "safe_when", health);
      add(hazard, "mitigated_by", health);
    });
    const matchingStates = key
      ? byType("target_state_transition").filter((item) => associationKey(item) === key)
      : byType("target_state_transition").filter((item) => !associationKey(item));
    matchingStates.forEach((state) => {
      add(hazard, "leaves_in_state", state);
      matchingRecoveries.forEach((recovery) => add(state, "requires_recovery", recovery));
      matchingRecoveries.forEach((recovery) => add(state, "mitigated_by", recovery));
    });
  }
  const topologyPatterns = byType("topology_pattern");
  for (const topology of topologyPatterns) {
    const key = topologyKey(topology);
    const roles = key
      ? byType("topology_role").filter((role) => topologyKey(role) === key)
      : (topologyPatterns.length === 1 ? byType("topology_role").filter((role) => !topologyKey(role)) : []);
    roles.forEach((role) => add(topology, "has_topology_role", role));
    if (topologyPatterns.length === 1) byType("discovery_pattern").forEach((discovery) => add(topology, "discovered_by", discovery));
    const attributes = key
      ? byType("attribute").filter((item) => topologyKey(item) === key)
      : [];
    attributes.forEach((item) => add(topology, "has_attribute", item));
  }
  const controls = [...byType("firewall"), ...byType("waf"), ...byType("proxy"), ...byType("security_control")];
  const attackConcepts = [...byType("attack_vector"), ...byType("attack_technique"), ...procedures];
  const controlBypassObserved = byType("attribute")
    .some((item) => item.title === "Control bypass observed" && parsedBody(item).controlBypass === true);
  if (controlBypassObserved) {
    attackConcepts.forEach((attack) => controls.forEach((control) => add(attack, "bypasses", control)));
  }
  return {
    facts: roleFacts,
    edges: [...edgeMap.values()].sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right))),
  };
}

function extractFacts(file: LegacyEngagementFile, text: string): Extraction {
  const facts: Fact[] = [];
  const extension = extname(file.relativePath).toLowerCase();
  const scopes = semanticScopes(text, extension === ".md");
  const products = collectProducts(text);
  for (const product of products) {
    facts.push(fact(product.nodeType, product.name,
      `Reusable ${product.nodeType.replaceAll("_", " ")} identity observed with an exact version fingerprint.`,
      {
        exactVersion: product.version,
        versionRole: product.nodeType === "kernel" ? "kernel_image"
          : product.nodeType === "operating_system" ? "operating_system_release" : "product_release",
      }, 0.94));
    facts.push(fact("exact_version_fingerprint", `${product.name} ${product.version}`,
      `Exact historical version fingerprint for ${product.name}; current applicability still requires fresh corroboration.`,
      {
        product: product.name,
        exactVersion: product.version,
        versionRole: product.nodeType === "kernel" ? "kernel_image"
          : product.nodeType === "operating_system" ? "operating_system_release" : "product_release",
        sourceClassification: "historical",
      }, 0.94));
  }
  for (const component of COMPONENT_PATTERNS.filter(({ expression }) => matched(expression, text))) {
    facts.push(fact(component.nodeType, component.name, component.summary,
      { exactFingerprintRequiredBeforeReuse: true }, 0.8));
  }

  const ranges = new Map<string, { product: string; expression: string }>();
  for (const product of products) {
    const escaped = product.name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const rangeExpression = new RegExp(`\\b${escaped}\\b[^\\r\\n]{0,40}?(?:versions?\\s+)?(\\d+(?:\\.\\d+){1,3}\\s*(?:through|to|-)\\s*\\d+(?:\\.\\d+){1,3}|(?:<|<=|>|>=)\\s*\\d+(?:\\.\\d+){1,3})`, "iu");
    const range = rangeExpression.exec(text)?.[1]?.replace(/\s+/gu, " ").trim();
    if (range) ranges.set(`${product.name}\0${range}`, { product: product.name, expression: range });
  }
  for (const range of [...ranges.values()].sort((a, b) => a.product.localeCompare(b.product) || a.expression.localeCompare(b.expression))) {
    facts.push(fact("version_range_fingerprint", `${range.product} affected range ${range.expression}`,
      `Historical affected-version range for ${range.product}; authoritative advisory validation is required.`,
      { product: range.product, rangeExpression: range.expression }, 0.78));
  }

  const cves = [...new Set(text.match(/\bCVE-\d{4}-\d{4,7}\b/giu)?.map((value) => value.toUpperCase()) ?? [])].sort();
  cves.forEach((id) => facts.push(fact("cve", id,
    `${id} was referenced by historical material and remains a candidate until authoritative applicability is verified.`,
    { identifier: id, applicability: "unreviewed" }, 0.82)));
  const cwes = [...new Set(text.match(/\bCWE-\d{1,5}\b/giu)?.map((value) => value.toUpperCase()) ?? [])].sort();
  cwes.forEach((id) => facts.push(fact("cwe", id,
    `${id} was referenced as a historical weakness classification.`, { identifier: id }, 0.82)));
  const advisories = [...new Set([
    ...(text.match(/\bGHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}\b/giu) ?? []),
    ...(text.match(/\bMS\d{2}-\d{3}\b/giu) ?? []),
  ].map((value) => value.toUpperCase()))].sort();
  advisories.forEach((id) => facts.push(fact("advisory", id,
    `${id} was referenced by historical material and requires authoritative source validation.`,
    { identifier: id, applicability: "unreviewed" }, 0.78)));

  const techniques = TECHNIQUES.filter(({ expression }) => matched(expression, text));
  for (const technique of techniques) {
    const applicableProducts = new Map<string, ProductMatch>();
    if (!PRODUCT_AGNOSTIC_TECHNIQUES.has(technique.name)) {
      for (const scope of scopes) {
        if (!matched(technique.expression, scope)) continue;
        const product = preferredScopedProduct(collectProducts(scope));
        if (product) applicableProducts.set(
          `${product.nodeType}\0${product.name}\0${product.version}`, product,
        );
      }
    }
    facts.push(fact(technique.nodeType, technique.name,
      `Reusable attack concept observed in historical material: ${technique.name}.`,
      {
        name: technique.name,
        classification: technique.nodeType,
        products: [...applicableProducts.values()].map((product) => ({
          name: product.name,
          exactVersion: product.version,
          nodeType: product.nodeType,
        })),
      }, 0.8));
  }
  const topologyRoles = TOPOLOGY_ROLES.filter(({ expression }) => matched(expression, text));
  if (topologyRoles.length > 0) {
    const key = `topology:${sha256("Layered service topology").slice(0, 24)}`;
    facts.push(fact("topology_pattern", "Layered service topology",
      "Reusable topology shape retained without hostnames, addresses, or engagement identity.",
      { roles: topologyRoles.map(({ name }) => name).sort(), topologyKey: key }, 0.76));
    for (const role of topologyRoles) {
      facts.push(fact("topology_role", role.name,
        `Reusable topology role observed in historical material: ${role.name}.`, { role: role.name, topologyKey: key }, 0.76));
    }
  }
  for (const topology of TOPOLOGY_PATTERNS) {
    if (!scopes.some((scope) => matchedScopedPattern(topology.match, scope))) continue;
    const key = `topology:${sha256(topology.name).slice(0, 24)}`;
    facts.push(fact("topology_pattern", topology.name, topology.summary,
      { roles: [...topology.roles].sort(), topologyKey: key }, 0.9));
    topology.roles.forEach((role) => facts.push(fact("topology_role", role,
      `Reusable role in the ${topology.name.toLowerCase()} pattern.`, { role, topologyKey: key }, 0.88)));
    topology.attributes?.forEach((attribute) => facts.push(fact("attribute", attribute,
      `Reusable control attribute of the ${topology.name.toLowerCase()} pattern.`, { attribute, topologyKey: key }, 0.9)));
  }
  if (techniques.length > 0 && /\bbypass(?:ed|es|ing)?\b/iu.test(text) &&
      products.some(({ nodeType }) => ["firewall", "waf", "proxy", "security_control"].includes(nodeType))) {
    facts.push(fact("attribute", "Control bypass observed",
      "A historical attack concept was reported to bypass a versioned security control; current applicability requires fresh validation.",
      { controlBypass: true }, 0.76));
  }
  for (const discovery of DISCOVERY_PATTERNS.filter(({ expression }) => matched(expression, text))) {
    facts.push(fact("discovery_pattern", discovery.name, discovery.summary,
      { pattern: discovery.name, sourceClassification: "historical" }, 0.76));
  }

  type ProcedureObservation = {
    name: string;
    summary: string;
    associationKey: string;
    products: Map<string, ProductMatch>;
    cves: Set<string>;
    prerequisites: Set<string>;
    normalizedAttributes: Record<string, string | number | boolean>;
    attackConcepts: Map<string, { name: string; nodeType: "attack_vector" | "attack_technique" }>;
  };
  const procedureObservations = new Map<string, ProcedureObservation>();
  const observeProcedure = (
    name: string,
    summary: string,
    key: string,
    scope: string,
    scopedProducts: readonly ProductMatch[],
    scopedAttackConcepts: readonly Readonly<{
      name: string;
      nodeType: "attack_vector" | "attack_technique";
    }>[],
  ): void => {
    const observed = procedureObservations.get(key) ?? {
      name,
      summary,
      associationKey: key,
      products: new Map<string, ProductMatch>(),
      cves: new Set<string>(),
      prerequisites: new Set<string>(),
      normalizedAttributes: {},
      attackConcepts: new Map(),
    };
    scopedProducts.forEach((product) => observed.products.set(
      `${product.nodeType}\0${product.name}\0${product.version}`, product,
    ));
    (scope.match(/\bCVE-\d{4}-\d{4,7}\b/giu) ?? []).forEach((id) => observed.cves.add(id.toUpperCase()));
    PREREQUISITES.filter(({ expression }) => matched(expression, scope))
      .forEach(({ name: prerequisite }) => observed.prerequisites.add(prerequisite));
    Object.assign(observed.normalizedAttributes, normalizedExecutionAttributes(scope));
    scopedAttackConcepts.forEach((concept) => observed.attackConcepts.set(
      `${concept.nodeType}\0${concept.name}`,
      { name: concept.name, nodeType: concept.nodeType },
    ));
    procedureObservations.set(key, observed);
  };

  let ambiguousAssociations = 0;
  const allFailureModes = new Set<string>();
  for (const scope of scopes) {
    const scopedProducts = collectProducts(scope);
    const scopedTechniques = TECHNIQUES.filter(({ expression }) => matched(expression, scope));
    const scopedProcedurePatterns = PROCEDURE_PATTERNS.filter(({ match }) => matchedScopedPattern(match, scope));
    for (const procedure of scopedProcedurePatterns) {
      observeProcedure(
        procedure.name,
        procedure.summary,
        procedureAssociationKey(procedure.name),
        scope,
        scopedProducts,
        scopedProcedurePatterns.length === 1 ? scopedTechniques : [],
      );
    }
    const preferredProduct = preferredScopedProduct(scopedProducts);
    let binding: { key: string; name: string; summary: string } | undefined;
    if (scopedProcedurePatterns.length === 1) {
      const procedure = scopedProcedurePatterns[0]!;
      binding = { key: procedureAssociationKey(procedure.name), name: procedure.name, summary: procedure.summary };
    } else if (scopedProcedurePatterns.length === 0 && scopedTechniques.length === 1 && preferredProduct &&
        !PRODUCT_AGNOSTIC_TECHNIQUES.has(scopedTechniques[0]!.name)) {
      const technique = scopedTechniques[0]!;
      const name = `${technique.name} procedure for ${preferredProduct.name} ${preferredProduct.version}`;
      binding = {
        key: genericAssociationKey(technique.name, preferredProduct),
        name,
        summary: `Historical ${technique.name.toLowerCase()} procedure candidate for a matching ${preferredProduct.name} technology fingerprint.`,
      };
      observeProcedure(binding.name, binding.summary, binding.key, scope, scopedProducts, [technique]);
    }

    const bodyAssociation = binding ? { associationKey: binding.key } : {};
    for (const attribute of ATTRIBUTES.filter(({ expression }) => matched(expression, scope))) {
      if (scopedTechniques.length || binding) facts.push(fact("attribute", attribute.name,
        `Normalized attack attribute observed with a historical procedure: ${attribute.name}.`,
        { attribute: attribute.name, ...bodyAssociation }, 0.76));
    }
    for (const attribute of FAILURE_ATTRIBUTES.filter(({ expression }) => matched(expression, scope))) {
      facts.push(fact("attribute", attribute.name,
        `Evidence-backed failure attribute retained to prevent repetition: ${attribute.name}.`,
        { attribute: attribute.name, failureRelated: true, ...bodyAssociation }, 0.9));
    }
    for (const prerequisite of PREREQUISITES.filter(({ expression }) => matched(expression, scope))) {
      if (scopedTechniques.length || binding) facts.push(fact("prerequisite", prerequisite.name,
        `Reusable procedure prerequisite: ${prerequisite.name}.`,
        { prerequisite: prerequisite.name, ...bodyAssociation }, 0.78));
    }
    for (const misconfiguration of MISCONFIGURATION_PATTERNS.filter(({ expression }) => matched(expression, scope))) {
      facts.push(fact("misconfiguration", misconfiguration.name, misconfiguration.summary,
        { misconfiguration: misconfiguration.name, ...bodyAssociation }, 0.88));
    }

    const failureModes = FAILURE_MODES.filter(({ expression }) => matched(expression, scope));
    failureModes.forEach(({ name }) => allFailureModes.add(name));
    const worked = /\b(?:worked|succeeded|successful|validated|confirmed impact|objective complete|obtained (?:SYSTEM|root)|produced (?:SYSTEM|root))\b/iu.test(scope);
    const failed = /\b(?:failed|did not work|unsuccessful|no effect|not applicable|not vulnerable|not reproduced)\b/iu.test(scope) || failureModes.length > 0;
    if ((worked || failed || failureModes.length > 0) && !binding) ambiguousAssociations += 1;
    if (binding && (worked || failed)) {
      const subject = preferredProduct ? `${binding.name} on ${preferredProduct.name} ${preferredProduct.version}` : binding.name;
      const common = {
        procedure: binding.name,
        associationKey: binding.key,
        ...(preferredProduct ? { product: preferredProduct.name, exactVersion: preferredProduct.version } : {}),
      };
      if (worked) facts.push(fact("outcome", `${subject}: reported successful result`,
        "Historical material reports a successful result for this bounded procedure and technology context. It remains supporting/unclassified until a canonical terminal AttackAttempt and verified evidence establish the outcome.",
        {
          reportedStatus: "worked",
          outcomeClassification: "unclassified",
          classificationBasis: "historical_text_only",
          ...common,
        }, 0.78));
      if (failed) facts.push(fact("outcome", `${subject}: reported unsuccessful result`,
        "Historical material reports a failed, unsafe, or non-reproduced result for this bounded procedure and technology context. It remains supporting/unclassified until a canonical terminal AttackAttempt and verified evidence establish the outcome.",
        {
          reportedStatus: "failed",
          outcomeClassification: "unclassified",
          classificationBasis: "historical_text_only",
          ...common,
        }, 0.82));
    }
    for (const mode of failureModes) {
      facts.push(fact("failure_mode", mode.name, mode.symptom,
        {
          failureMode: mode.name,
          ...(mode.causeCategory ? { causeCategory: mode.causeCategory } : {}),
          ...(preferredProduct ? { product: preferredProduct.name, exactVersion: preferredProduct.version } : {}),
          ...(binding ? { procedure: binding.name, associationKey: binding.key } : {}),
        }, 0.86));
    }
    for (const recovery of RECOVERY_PATTERNS.filter(({ expression }) => matched(expression, scope))) {
      facts.push(fact("recovery_pattern", recovery.name, recovery.summary,
        { recoveryPattern: recovery.name, ...bodyAssociation }, 0.84));
    }
    for (const health of HEALTH_CHECKS.filter(({ expression }) => matched(expression, scope))) {
      facts.push(fact("health_check", health.name, health.summary,
        { healthCheck: health.name, ...bodyAssociation }, 0.88));
    }
    if (failureModes.length && /\b(?:retry|repeat|rerun|again|refire|re-fire)\b/iu.test(scope)) {
      facts.push(fact("operational_hazard", "Do not repeat an unresolved failed procedure",
        "A procedure that produced a hang, timeout, crash, or unavailable service must not be repeated until the affected execution path is proven healthy.",
        {
          unsafeRetryCondition: "The preceding attempt has no trustworthy terminal result or the affected execution path has not passed its health check",
          matchingRequired: ["exact technology fingerprint", "exact procedure or script hash", "normalized execution attributes", "pre-execution state"],
          ...bodyAssociation,
        }, 0.92));
    }
  }

  if (file.kind === "script") {
    const language = safeScriptLanguage(extension);
    facts.push(fact("script_artifact", `${language} procedure artifact ${file.sha256.slice(0, 16)}`,
      `Exact historical ${language} script artifact retained by content hash for review and controlled reuse.`,
      { language, contentHash: file.sha256, sourceRetainedPrivately: true }, 1));
  }
  for (const observation of [...procedureObservations.values()].sort((left, right) => left.name.localeCompare(right.name))) {
    const productBindings = [...observation.products.values()].map((product) => ({
      name: product.name,
      exactVersion: product.version,
      nodeType: product.nodeType,
    }));
    facts.push(fact("attack_procedure", observation.name, observation.summary,
      {
        associationKey: observation.associationKey,
        products: productBindings,
        cves: [...observation.cves].sort(),
        normalizedAttributes: Object.fromEntries(Object.entries(observation.normalizedAttributes).sort(([left], [right]) => left.localeCompare(right))),
        prerequisites: [...observation.prerequisites].sort(),
        attackConcepts: [...observation.attackConcepts.values()].sort((left, right) =>
          left.nodeType.localeCompare(right.nodeType) || left.name.localeCompare(right.name)),
        ...(file.kind === "script" ? {
          procedureVersion: `sha256:${file.sha256}`,
          scriptContentHash: file.sha256,
        } : {}),
      }, file.kind === "script" ? 0.9 : 0.84));
  }

  const resetMinimum = /\bmore than\s+(\d{1,4})\s+(?:resets?|times)\b/iu.exec(text)?.[1]
    ?? /\b(?:reset|reboot)(?:ted)?\b[^\r\n]{0,30}?\b(\d{1,4})\s+times\b/iu.exec(text)?.[1];
  if (resetMinimum && allFailureModes.size > 0) {
    const minimum = Math.min(10_000, Number(resetMinimum) + (/\bmore than\b/iu.test(text) ? 1 : 0));
    facts.push(fact("attack_lesson", `At least ${minimum} environment recoveries followed unresolved failures`,
      "Historical aggregate recovery cost is retained without assigning unattributed resets to a specific procedure.",
      { operatorReportedRecoveryCountMinimum: minimum, attribution: "aggregate_only" }, 0.95));
  }

  const exactProcedureHashes = [...new Set(text.match(/\bsha256\s*[:=]\s*([a-f0-9]{64})\b/giu)?.map((match) => match.replace(/^.*[:=]\s*/u, "").toLowerCase()) ?? [])];
  exactProcedureHashes.filter((hash) => SHA256.test(hash)).sort().forEach((hash) => {
    facts.push(fact("procedure_version", `Procedure version ${hash.slice(0, 16)}`,
      "Exact historical procedure version retained by SHA-256 content hash.", { contentHash: hash }, 1));
  });

  const unique = new Map<string, Fact>();
  for (const candidate of facts) {
    const key = sha256(canonicalJson(candidate));
    if (!unique.has(key)) unique.set(key, candidate);
  }
  const versionishCount = text.match(/\b\d+(?:\.\d+){2,3}\b/gu)?.length ?? 0;
  const connected = connectedFacts([...unique.values()].sort((left, right) =>
    left.nodeType.localeCompare(right.nodeType) || left.title.localeCompare(right.title)));
  // A historical scripts directory is often a general operator toolbox rather
  // than evidence that every file participated in an attack. Retaining one
  // reusable script node for every file created thousands of isolated hashes
  // that could not be applied to a technology, procedure, or observed result.
  // Keep a script artifact only when this exact hash-verified file produced a
  // typed relationship to another fact in the same bundle. This deliberately
  // does not infer a relationship from directory placement, engagement
  // membership, or cross-file co-occurrence.
  const relatedRoles = new Set(connected.edges.flatMap(({ sourceRole, targetRole }) => (
    [sourceRole, targetRole]
  )));
  const retainedFacts = file.kind === "script"
    ? connected.facts.filter((item) => (
        item.nodeType !== "script_artifact" || relatedRoles.has(item.role)
      ))
    : connected.facts;
  const retainedRoles = new Set(retainedFacts.map(({ role }) => role));
  const retainedEdges = connected.edges.filter(({ sourceRole, targetRole }) => (
    retainedRoles.has(sourceRole) && retainedRoles.has(targetRole)
  ));
  return {
    facts: retainedFacts,
    edges: retainedEdges,
    ambiguousFragments: Math.max(0, versionishCount - products.length) +
      (techniques.length > 0 && products.length === 0 ? techniques.length : 0) +
      ambiguousAssociations,
  };
}

export type HistoricalAttackExtractionIssueReason =
  | "unsupported_source"
  | "raw_log_not_summary"
  | "file_budget_exceeded"
  | "total_budget_exceeded"
  | "source_changed"
  | "read_failed"
  | "malformed_text"
  | "secret_bearing_source"
  | "secret_bearing_segment"
  | "no_reusable_semantics"
  | "candidate_budget_exceeded";

export interface HistoricalAttackExtractionIssue {
  /** Opaque key only; source paths and engagement labels stay private. */
  readonly sourceKey: string;
  readonly disposition: "skipped" | "quarantined" | "ambiguous";
  readonly reason: HistoricalAttackExtractionIssueReason;
  readonly count?: number;
}

export interface HistoricalAttackKnowledgeExtractionResult {
  readonly status: "completed" | "partial";
  readonly dryRun: boolean;
  readonly manifestFingerprint: string;
  readonly filesDiscovered: number;
  readonly filesParsed: number;
  readonly filesSkipped: number;
  readonly filesQuarantined: number;
  readonly bytesParsed: number;
  readonly semanticFactsParsed: number;
  readonly ambiguousFragments: number;
  readonly compilerBundlesStaged: number;
  readonly candidatesCreated: number;
  readonly candidatesReused: number;
  readonly sourceEvidenceCandidatesCreated: number;
  readonly sourceEvidenceCandidatesReused: number;
  readonly sourceBundleLinks: number;
  /** Exact global compiler state after this bounded batch's single reconciliation pass. */
  readonly compilerReconciliation: AttackKnowledgeReconciliation;
  readonly compilerReconciliationPasses: 1;
  readonly compilerRunsReconciled: number;
  readonly nodeTypeCounts: Readonly<Record<string, number>>;
  readonly edgeTypeCounts: Readonly<Record<string, number>>;
  /** Opaque source-evidence candidate IDs grouped by proposed edge type.
   * This is intentionally path-free so a dry run can be audited without
   * disclosing engagement labels, targets, or private filesystem locations. */
  readonly edgeSourceEvidenceCandidateIds: Readonly<Record<string, readonly string[]>>;
  readonly nextResumeAfterSourceKey?: string;
  readonly candidateIds: readonly string[];
  readonly sourceEvidenceCandidateIds: readonly string[];
  readonly issues: readonly HistoricalAttackExtractionIssue[];
}

function incrementDistribution(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1;
}

function addKnowledgeDistribution(
  knowledge: ReusableAttackBundleKnowledge | ReusableAttackFactKnowledge,
  nodeTypeCounts: Record<string, number>,
  edgeTypeCounts: Record<string, number>,
): void {
  if (knowledge.kind === "reusable_fact") {
    incrementDistribution(nodeTypeCounts, knowledge.nodeType);
    return;
  }
  knowledge.facts.forEach(({ nodeType }) => incrementDistribution(nodeTypeCounts, nodeType));
  knowledge.edges.forEach(({ edgeType }) => incrementDistribution(edgeTypeCounts, edgeType));
}

export interface HistoricalAttackKnowledgeExtractionOptions {
  readonly receiptHmacKey: string | Buffer;
  readonly maxFiles?: number;
  readonly maxFileBytes?: number;
  readonly maxTotalBytes?: number;
  readonly maxFactsPerFile?: number;
  readonly clock?: () => Date;
}

export interface HistoricalAttackKnowledgeExtractRequest {
  readonly dryRun?: boolean;
  /** Resume strictly after this opaque source key. Rerunning without it is also idempotent. */
  readonly resumeAfterSourceKey?: string;
  /** Optional bounded batch size for deterministic interruption/resume tests and jobs. */
  readonly maxFilesThisRun?: number;
}

export interface HistoricalAttackSourceEvidenceReviewRequest {
  readonly candidateId: string;
  readonly actorId: string;
  readonly reason: string;
  readonly expectedSourceHash: string;
}

export interface HistoricalAttackSourceEvidenceReviewResult {
  readonly candidateId: string;
  readonly evidenceId: string;
  readonly sourceHash: string;
  readonly bundleBindingsCreated: number;
  readonly auditRecordId: string;
  readonly status: "verified" | "replayed";
}

interface SourceInventoryBinding {
  readonly migrationId: string;
  readonly sourceReference: string;
  readonly sourcePath?: string;
  readonly sourceHash: string;
  readonly byteSize: number;
  readonly modifiedAt: string;
  readonly sourceDevice?: number;
  readonly sourceInode?: number;
}

export interface HistoricalAttackSourceEvidenceReviewStartResult {
  readonly candidateId: string;
  readonly status: "validating" | "replayed";
  readonly auditRecordId?: string;
}

/**
 * Deterministic, local-only historical semantic extractor. It never invokes a
 * provider or public LLM, never retains source excerpts, and only stages
 * pending AttackKnowledgeCompiler candidates. Private source identity is used
 * transiently to derive the compiler's opaque provenance receipt.
 */
export class HistoricalAttackKnowledgeExtractionService {
  readonly #database: SqliteDatabase;
  readonly #compiler: AttackKnowledgeCompiler;
  readonly #audit: AuditTrailWriter;
  readonly #key: Buffer;
  readonly #clock: () => Date;
  readonly #maxFiles: number;
  readonly #maxFileBytes: number;
  readonly #maxTotalBytes: number;
  readonly #maxFactsPerFile: number;

  constructor(database: SqliteDatabase, options: HistoricalAttackKnowledgeExtractionOptions) {
    const key = Buffer.isBuffer(options.receiptHmacKey)
      ? options.receiptHmacKey
      : Buffer.from(options.receiptHmacKey, "utf8");
    if (key.byteLength < 32) throw new TypeError("Historical attack extraction receipt key must contain at least 32 bytes");
    this.#database = database;
    this.#key = Buffer.from(key);
    this.#clock = options.clock ?? (() => new Date());
    this.#compiler = new AttackKnowledgeCompiler(database, { receiptHmacKey: key, clock: this.#clock });
    this.#audit = new AuditTrailWriter(database);
    this.#maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
    this.#maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.#maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
    this.#maxFactsPerFile = options.maxFactsPerFile ?? DEFAULT_MAX_FACTS_PER_FILE;
    for (const [label, value] of Object.entries({
      maxFiles: this.#maxFiles,
      maxFileBytes: this.#maxFileBytes,
      maxTotalBytes: this.#maxTotalBytes,
      maxFactsPerFile: this.#maxFactsPerFile,
    })) {
      if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} must be a positive safe integer`);
    }
  }

  #hmac(value: string): string {
    return createHmac("sha256", this.#key).update(value, "utf8").digest("hex");
  }

  #tableExists(name: string): boolean {
    return Boolean(this.#database.prepare(
      "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?",
    ).get(name));
  }

  #sourceInventory(
    file: LegacyEngagementFile,
    manifestFingerprint: string,
  ): SourceInventoryBinding {
    if (this.#tableExists("legacy_migration_source_objects")) {
      const row = this.#database.prepare(`
        SELECT migration_id, source_reference, source_path, source_sha256,
          byte_size, modified_at, source_device, source_inode
        FROM legacy_migration_source_objects
        WHERE source_path = ? AND source_sha256 = ? AND byte_size = ?
          AND modified_at = ? AND object_kind = 'accepted'
          AND verification_status = 'verified_reference'
        ORDER BY verified_at DESC, id DESC LIMIT 1
      `).get(file.absolutePath, file.sha256, file.byteSize, file.modifiedAt) as {
        readonly migration_id: string;
        readonly source_reference: string;
        readonly source_path: string;
        readonly source_sha256: string;
        readonly byte_size: number;
        readonly modified_at: string;
        readonly source_device: number;
        readonly source_inode: number;
      } | undefined;
      if (row) {
        return {
          migrationId: row.migration_id,
          sourceReference: row.source_reference,
          sourcePath: row.source_path,
          sourceHash: row.source_sha256,
          byteSize: Number(row.byte_size),
          modifiedAt: row.modified_at,
          sourceDevice: Number(row.source_device),
          sourceInode: Number(row.source_inode),
        };
      }
    }
    // Unit/standalone callers may stage candidates, but cannot verify them
    // until the verified-reference inventory is reconciled. No path is stored.
    return {
      migrationId: `standalone_${this.#hmac(manifestFingerprint).slice(0, 40)}`,
      sourceReference: `legacy-private-source://${this.#hmac(`source\0${file.absolutePath}`).slice(0, 48)}`,
      sourceHash: file.sha256,
      byteSize: file.byteSize,
      modifiedAt: file.modifiedAt,
    };
  }

  #contextIds(migrationId: string): { readonly missionId: string; readonly runId: string } {
    const digest = this.#hmac(`context\0${migrationId}`).slice(0, 40);
    return { missionId: `mission_hak_import_${digest}`, runId: `run_hak_import_${digest}` };
  }

  #ensureImportContext(binding: SourceInventoryBinding): {
    readonly missionId: string;
    readonly runId: string;
  } {
    const ids = this.#contextIds(binding.migrationId);
    const now = this.#clock().toISOString();
    this.#database.prepare(`
      INSERT OR IGNORE INTO missions (
        id, name, objective, journey, status, authorization_status,
        scope_json, success_criteria_json, retention_policy_json, memory_policy_json,
        created_by, version, created_at, updated_at, control_plane
      ) VALUES (?, 'Internal historical attack-knowledge import',
        'Private local source-custody context; not an executable engagement.',
        'guided', 'archived', 'unverified', '{}', '[]', ?, ?,
        'system:historical-attack-knowledge-import', 1, ?, ?, 'ti_scale')
    `).run(
      ids.missionId,
      canonicalJson({ internalOnly: true, preserveSourceCustody: true }),
      canonicalJson({ reusableRetrieval: false, allowAutonomous: false, projectToBrain: false }),
      now,
      now,
    );
    this.#database.prepare(`
      INSERT OR IGNORE INTO runs (
        id, mission_id, journey, status, progress, status_reason,
        next_action_summary, budget_json, budget_usage_json, retry_count,
        replan_count, started_at, ended_at, created_at, updated_at, version,
        control_plane
      ) VALUES (?, ?, 'guided', 'completed', 1,
        'Internal source-custody context completed; candidates await independent review.',
        'Review hash-bound evidence candidates', '{}', '{}', 0, 0,
        ?, ?, ?, ?, 1, 'ti_scale')
    `).run(ids.runId, ids.missionId, now, now, now, now);
    this.#database.prepare(`
      INSERT INTO historical_attack_knowledge_import_contexts (
        migration_id, mission_id, run_id, created_at
      ) VALUES (?, ?, ?, ?) ON CONFLICT(migration_id) DO NOTHING
    `).run(binding.migrationId, ids.missionId, ids.runId, now);
    const context = this.#database.prepare(`
      SELECT mission_id, run_id FROM historical_attack_knowledge_import_contexts
      WHERE migration_id = ?
    `).get(binding.migrationId) as { readonly mission_id: string; readonly run_id: string } | undefined;
    if (!context || context.mission_id !== ids.missionId || context.run_id !== ids.runId) {
      throw new Error("Historical attack import context reconciliation failed");
    }
    return ids;
  }

  #sourceCandidateId(binding: SourceInventoryBinding): string {
    return `candidate_hak_source_${this.#hmac(`content\0${binding.sourceHash}\0${binding.byteSize}`).slice(0, 48)}`;
  }

  #sourceCandidateExists(candidateId: string): boolean {
    return Boolean(this.#database.prepare(
      "SELECT 1 AS present FROM historical_attack_knowledge_source_candidates WHERE candidate_id = ?",
    ).get(candidateId));
  }

  #stageSourceEvidenceCandidate(
    binding: SourceInventoryBinding,
  ): { readonly id: string; readonly created: boolean } {
    const candidateId = this.#sourceCandidateId(binding);
    const existing = this.#database.prepare(`
      SELECT source_hash, byte_size
      FROM historical_attack_knowledge_source_candidates WHERE candidate_id = ?
    `).get(candidateId) as {
      readonly source_hash: string;
      readonly byte_size: number;
    } | undefined;
    if (existing) {
      if (existing.source_hash !== binding.sourceHash || Number(existing.byte_size) !== binding.byteSize) {
        throw new Error("Historical attack source candidate immutable identity mismatch");
      }
      this.#ensureImportContext(binding);
      this.#stageSourceOccurrence(candidateId, binding);
      return { id: candidateId, created: false };
    }
    const context = this.#ensureImportContext(binding);
    const now = this.#clock().toISOString();
    this.#database.prepare(`
      INSERT INTO evidence_candidates (
        id, mission_id, run_id, observation_id, artifact_id, evidence_type,
        label, meaning, promotion_reason, validation_requirements_json,
        state, sensitivity, proposed_by, created_at
      ) VALUES (?, ?, ?, NULL, NULL, 'historical_attack_source_record',
        'Historical attack-knowledge source record',
        'Hash-verified local source supporting one or more generalized attack-knowledge candidates.',
        'Independent review must re-hash the private local source and validate the reusable semantic claims before promotion.',
        ?, 'candidate', 'private', 'system:historical-attack-knowledge-extractor', ?)
    `).run(
      candidateId,
      context.missionId,
      context.runId,
      canonicalJson([
        "Revalidate source device, inode, byte size, modification time, and SHA-256",
        "Review each generalized claim against the private source",
        "Confirm no target identity, address, journey metadata, or secret enters reusable memory",
      ]),
      now,
    );
    this.#database.prepare(`
      INSERT INTO historical_attack_knowledge_source_candidates (
        candidate_id, source_hash, byte_size, created_at
      ) VALUES (?, ?, ?, ?)
    `).run(
      candidateId,
      binding.sourceHash,
      binding.byteSize,
      now,
    );
    this.#stageSourceOccurrence(candidateId, binding);
    this.#audit.append({
      missionId: context.missionId,
      runId: context.runId,
      actor: { type: "system", id: "historical-attack-knowledge-extractor" },
      action: "evidence_candidate.proposed",
      resourceType: "evidence_candidate",
      resourceId: candidateId,
      reason: "A locally parsed reusable bundle requires independently reviewed source custody.",
      details: { sourceReference: binding.sourceReference, sourceHash: binding.sourceHash },
      occurredAt: now,
    });
    return { id: candidateId, created: true };
  }

  #stageSourceOccurrence(candidateId: string, binding: SourceInventoryBinding): void {
    const now = this.#clock().toISOString();
    this.#database.prepare(`
      INSERT INTO historical_attack_knowledge_source_occurrences (
        candidate_id, migration_id, source_reference, source_hash, modified_at, observed_at
      ) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(candidate_id, migration_id, source_reference) DO NOTHING
    `).run(
      candidateId,
      binding.migrationId,
      binding.sourceReference,
      binding.sourceHash,
      binding.modifiedAt,
      now,
    );
  }

  #linkSourceEvidenceCandidate(
    bundleId: string,
    receiptId: string,
    candidateId: string,
    binding: SourceInventoryBinding,
  ): number {
    const now = this.#clock().toISOString();
    const bindingHash = this.#hmac(canonicalJson({
      bundleId, receiptId, candidateId, sourceHash: binding.sourceHash,
    }));
    return this.#database.prepare(`
      INSERT INTO historical_attack_knowledge_bundle_sources (
        bundle_id, receipt_id, candidate_id, source_hash, binding_hash, linked_at
      ) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(bundle_id, receipt_id, candidate_id) DO NOTHING
    `).run(bundleId, receiptId, candidateId, binding.sourceHash, bindingHash, now).changes;
  }

  beginSourceEvidenceReview(input: Omit<HistoricalAttackSourceEvidenceReviewRequest, "expectedSourceHash">): HistoricalAttackSourceEvidenceReviewStartResult {
    const candidateId = input.candidateId.trim();
    const actorId = input.actorId.trim();
    const reason = input.reason.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}$/u.test(candidateId) ||
        !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}$/u.test(actorId) || !reason || reason.length > 2_000) {
      throw new TypeError("Historical source review identifiers or reason are invalid");
    }
    return inImmediateTransaction(this.#database, () => {
      const row = this.#database.prepare(`
        SELECT candidate.state, candidate.reviewed_by,
          candidate.mission_id, candidate.run_id
        FROM evidence_candidates candidate
        JOIN historical_attack_knowledge_source_candidates source ON source.candidate_id = candidate.id
        WHERE candidate.id = ?
      `).get(candidateId) as {
        readonly state: string;
        readonly reviewed_by: string | null;
        readonly mission_id: string;
        readonly run_id: string;
      } | undefined;
      if (!row) throw new Error("Historical attack source evidence candidate was not found");
      if (row.state === "validating" && row.reviewed_by === actorId) return { candidateId, status: "replayed" };
      if (row.state !== "candidate") throw new Error(`Historical attack source candidate cannot enter review from ${row.state}`);
      const now = this.#clock().toISOString();
      this.#database.prepare(`
        UPDATE evidence_candidates SET state = 'validating', reviewed_by = ?,
          review_reason = ?, reviewed_at = ? WHERE id = ? AND state = 'candidate'
      `).run(actorId, reason, now, candidateId);
      const auditRecordId = this.#audit.append({
        missionId: row.mission_id,
        runId: row.run_id,
        actor: { type: "operator", id: actorId },
        action: "historical_attack_source.review_started",
        resourceType: "evidence_candidate",
        resourceId: candidateId,
        reason,
        details: { candidateId },
        occurredAt: now,
      });
      return { candidateId, status: "validating", auditRecordId };
    });
  }

  verifySourceEvidence(input: HistoricalAttackSourceEvidenceReviewRequest): HistoricalAttackSourceEvidenceReviewResult {
    const candidateId = input.candidateId.trim();
    const actorId = input.actorId.trim();
    const reason = input.reason.trim();
    const expectedSourceHash = input.expectedSourceHash.trim().toLowerCase();
    if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}$/u.test(candidateId) ||
        !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}$/u.test(actorId) || !reason || reason.length > 2_000 ||
        !SHA256.test(expectedSourceHash)) {
      throw new TypeError("Historical source verification input is invalid");
    }
    const source = this.#database.prepare(`
      SELECT source.candidate_id, occurrence.source_reference, source.source_hash,
        source.byte_size, occurrence.modified_at, candidate.state,
        candidate.reviewed_by, candidate.promoted_evidence_id,
        candidate.mission_id, candidate.run_id,
        inventory.source_path, inventory.source_device, inventory.source_inode,
        inventory.verification_status
      FROM historical_attack_knowledge_source_candidates source
      JOIN evidence_candidates candidate ON candidate.id = source.candidate_id
      JOIN historical_attack_knowledge_source_occurrences occurrence
        ON occurrence.candidate_id = source.candidate_id
      LEFT JOIN legacy_migration_source_objects inventory
        ON inventory.source_reference = occurrence.source_reference
        AND inventory.migration_id = occurrence.migration_id
      WHERE source.candidate_id = ?
      ORDER BY CASE WHEN inventory.verification_status = 'verified_reference' THEN 0 ELSE 1 END,
        inventory.verified_at DESC, occurrence.observed_at DESC
      LIMIT 1
    `).get(candidateId) as {
      readonly candidate_id: string;
      readonly source_reference: string;
      readonly source_hash: string;
      readonly byte_size: number;
      readonly modified_at: string;
      readonly state: string;
      readonly reviewed_by: string | null;
      readonly promoted_evidence_id: string | null;
      readonly mission_id: string;
      readonly run_id: string;
      readonly source_path: string | null;
      readonly source_device: number | null;
      readonly source_inode: number | null;
      readonly verification_status: string | null;
    } | undefined;
    if (!source) throw new Error("Historical attack source evidence candidate was not found");
    if (source.source_hash !== expectedSourceHash) throw new Error("Expected historical source hash does not match the staged candidate");
    if (source.state === "promoted" && source.promoted_evidence_id) {
      const replay = this.#database.prepare(`
        SELECT verification_audit_id FROM historical_attack_knowledge_verified_bundle_links
        WHERE candidate_id = ? AND evidence_id = ? ORDER BY bundle_id LIMIT 1
      `).get(candidateId, source.promoted_evidence_id) as { readonly verification_audit_id: string } | undefined;
      return {
        candidateId,
        evidenceId: source.promoted_evidence_id,
        sourceHash: source.source_hash,
        bundleBindingsCreated: 0,
        auditRecordId: replay?.verification_audit_id ?? "audit_reconciled",
        status: "replayed",
      };
    }
    if (source.state !== "validating" || source.reviewed_by !== actorId) {
      throw new Error("Historical source must be placed in validating review by this operator before verification");
    }
    if (!source.source_path || source.verification_status !== "verified_reference" ||
        source.source_device === null || source.source_inode === null) {
      throw new Error("Private verified-reference source inventory is unavailable; reconcile the import before verification");
    }

    const revalidate = (): void => {
      readPinnedSource(source.source_path!, {
        sourceHash: source.source_hash,
        byteSize: Number(source.byte_size),
        modifiedAt: source.modified_at,
        sourceDevice: source.source_device!,
        sourceInode: source.source_inode!,
      });
    };
    revalidate();
    return inImmediateTransaction(this.#database, () => {
      revalidate();
      const now = this.#clock().toISOString();
      const evidenceId = `evidence_hak_source_${this.#hmac(`${candidateId}\0${source.source_hash}`).slice(0, 48)}`;
      this.#database.prepare(`
        INSERT INTO evidence (
          id, mission_id, run_id, source, acquired_at, target, evidence_type,
          content_hash, provenance_json, confidence, sensitivity,
          verification_state, summary, created_by, created_at
        ) VALUES (?, ?, ?, 'Local verified-reference historical import', ?,
          'Reusable attack-knowledge source', 'historical_attack_source_record', ?, ?,
          1, 'private', 'verified',
          'Independently re-hashed local source supporting reviewed reusable attack knowledge.',
          ?, ?)
      `).run(
        evidenceId,
        source.mission_id,
        source.run_id,
        source.modified_at,
        source.source_hash,
        canonicalJson({
          method: "local_hash_revalidation",
          sourceReference: source.source_reference,
          candidateId,
          sourceHash: source.source_hash,
          rawContentRetained: false,
        }),
        actorId,
        now,
      );
      const custody = this.#database.prepare(`
        INSERT INTO evidence_chain_events (
          id, evidence_id, event_type, actor, details_json, occurred_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `);
      for (const [ordinal, eventType] of ["acquired", "stored", "validated", "verified"].entries()) {
        custody.run(
          `custody_hak_${this.#hmac(`${evidenceId}\0${eventType}`).slice(0, 48)}`,
          evidenceId,
          eventType,
          actorId,
          canonicalJson({ ordinal, sourceReference: source.source_reference, sourceHash: source.source_hash }),
          now,
        );
      }
      this.#database.prepare(`
        UPDATE evidence_candidates SET state = 'promoted', promoted_evidence_id = ?,
          review_reason = ?, reviewed_at = ?
        WHERE id = ? AND state = 'validating' AND reviewed_by = ?
      `).run(evidenceId, reason, now, candidateId, actorId);
      const changed = this.#database.prepare("SELECT changes() AS count").get() as { readonly count: number };
      if (Number(changed.count) !== 1) throw new Error("Historical source candidate changed during verification");
      const auditRecordId = this.#audit.append({
        missionId: source.mission_id,
        runId: source.run_id,
        actor: { type: "operator", id: actorId },
        action: "historical_attack_source.verified",
        resourceType: "evidence_candidate",
        resourceId: candidateId,
        reason,
        details: { evidenceId, sourceReference: source.source_reference, sourceHash: source.source_hash },
        occurredAt: now,
      });
      const rows = this.#database.prepare(`
        SELECT bundle_id, receipt_id FROM historical_attack_knowledge_bundle_sources
        WHERE candidate_id = ? ORDER BY bundle_id, receipt_id
      `).all(candidateId) as Array<{ readonly bundle_id: string; readonly receipt_id: string }>;
      let bundleBindingsCreated = 0;
      for (const row of rows) {
        bundleBindingsCreated += this.#database.prepare(`
          INSERT INTO attack_knowledge_bundle_evidence_bindings (
            bundle_id, receipt_id, evidence_id, content_hash, acquired_at, bound_at
          ) VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(bundle_id, evidence_id) DO NOTHING
        `).run(row.bundle_id, row.receipt_id, evidenceId, source.source_hash, source.modified_at, now).changes;
        this.#database.prepare(`
          INSERT INTO historical_attack_knowledge_verified_bundle_links (
            bundle_id, receipt_id, candidate_id, evidence_id, source_hash,
            verification_audit_id, verified_by, verified_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(bundle_id, receipt_id, evidence_id) DO NOTHING
        `).run(
          row.bundle_id,
          row.receipt_id,
          candidateId,
          evidenceId,
          source.source_hash,
          auditRecordId,
          actorId,
          now,
        );
      }
      return {
        candidateId,
        evidenceId,
        sourceHash: source.source_hash,
        bundleBindingsCreated,
        auditRecordId,
        status: "verified",
      };
    });
  }

  extract(
    manifest: LegacyEngagementManifest,
    request: HistoricalAttackKnowledgeExtractRequest = {},
  ): HistoricalAttackKnowledgeExtractionResult {
    const dryRun = request.dryRun === true;
    const reusableQuarantineReferences = reusableMarkdownQuarantineReferences(manifest);
    const sourceFiles = [...manifest.files, ...reusableQuarantineReferences];
    const manifestFingerprint = sha256(canonicalJson({
      schemaVersion: 1,
      manifestHash: manifest.sha256,
      files: manifest.files.map(({ relativePath, sha256: sourceHash, byteSize, modifiedAt, kind }) => ({
        relativePath,
        sourceHash,
        byteSize,
        modifiedAt,
        kind,
      })),
      ...(reusableQuarantineReferences.length > 0 ? {
        reusableQuarantineReferences: reusableQuarantineReferences.map(
          ({ relativePath, sha256: sourceHash, byteSize, modifiedAt }) => ({
            relativePath,
            sourceHash,
            byteSize,
            modifiedAt,
            extractionPolicy: "independent-safe-markdown-segments-v1",
          }),
        ),
      } : {}),
    }));
    const eligible = sourceFiles
      .map((file) => ({
        file,
        sourceKey: sha256(`${manifestFingerprint}\0${file.relativePath}\0${file.sha256}\0${file.kind}`),
      }))
      .sort((left, right) => left.sourceKey.localeCompare(right.sourceKey));
    let startIndex = 0;
    if (request.resumeAfterSourceKey) {
      const index = eligible.findIndex(({ sourceKey }) => sourceKey === request.resumeAfterSourceKey);
      if (index < 0) throw new TypeError("resumeAfterSourceKey is not part of this manifest fingerprint");
      startIndex = index + 1;
    }
    const requestedBatchMaximum = request.maxFilesThisRun ?? this.#maxFiles;
    if (!Number.isSafeInteger(requestedBatchMaximum) || requestedBatchMaximum < 1) {
      throw new TypeError("maxFilesThisRun must be a positive safe integer");
    }
    const batchMaximum = Math.min(requestedBatchMaximum, this.#maxFiles);
    const maxCompilerRequests = batchMaximum * this.#maxFactsPerFile;
    if (!Number.isSafeInteger(maxCompilerRequests) || maxCompilerRequests < 1) {
      throw new RangeError("Historical attack extraction compiler batch bound is invalid");
    }
    const compilerBatch = this.#compiler.beginDeferredReconciliationBatch({
      maxCompilations: maxCompilerRequests,
    });
    const issues: HistoricalAttackExtractionIssue[] = [];
    const candidateIds = new Set<string>();
    const sourceEvidenceCandidateIds = new Set<string>();
    let filesParsed = 0;
    let filesSkipped = 0;
    let filesQuarantined = 0;
    let bytesParsed = 0;
    let bytesConsumedThisRun = 0;
    let semanticFactsParsed = 0;
    let ambiguousFragments = 0;
    let compilerBundlesStaged = 0;
    let candidatesCreated = 0;
    let candidatesReused = 0;
    let sourceEvidenceCandidatesCreated = 0;
    let sourceEvidenceCandidatesReused = 0;
    let sourceBundleLinks = 0;
    const nodeTypeCounts: Record<string, number> = {};
    const edgeTypeCounts: Record<string, number> = {};
    const edgeSourceEvidenceCandidateIds = new Map<string, Set<string>>();
    let processedThisRun = 0;
    let lastProcessedSourceKey: string | undefined;

    for (let index = startIndex; index < eligible.length; index += 1) {
      if (processedThisRun >= batchMaximum) break;
      const { file, sourceKey } = eligible[index]!;
      const markProcessed = (): void => {
        processedThisRun += 1;
        lastProcessedSourceKey = sourceKey;
      };
      const extension = extname(file.relativePath).toLowerCase();
      if (!ELIGIBLE_KINDS.has(file.kind) || !TEXT_EXTENSIONS.has(extension) || !["text", "structured"].includes(file.contentClass)) {
        markProcessed();
        filesSkipped += 1;
        issues.push({ sourceKey, disposition: "skipped", reason: "unsupported_source" });
        continue;
      }
      if (file.kind === "log" && !SUMMARY_LOG_NAME.test(basename(file.relativePath))) {
        markProcessed();
        filesSkipped += 1;
        issues.push({ sourceKey, disposition: "skipped", reason: "raw_log_not_summary" });
        continue;
      }
      if (file.byteSize > this.#maxFileBytes) {
        markProcessed();
        filesSkipped += 1;
        issues.push({ sourceKey, disposition: "skipped", reason: "file_budget_exceeded" });
        continue;
      }
      if (file.byteSize > this.#maxTotalBytes) {
        markProcessed();
        filesSkipped += 1;
        issues.push({ sourceKey, disposition: "skipped", reason: "total_budget_exceeded" });
        continue;
      }
      if (bytesConsumedThisRun + file.byteSize > this.#maxTotalBytes) {
        // Leave this source unconsumed. The opaque cursor points to the prior
        // source, so the next bounded batch starts here instead of losing it.
        break;
      }
      markProcessed();
      bytesConsumedThisRun += file.byteSize;
      let bytes: Buffer;
      const sourceInventory = this.#sourceInventory(file, manifestFingerprint);
      try {
        bytes = readPinnedSource(file.absolutePath, sourceInventory);
      } catch (error) {
        filesQuarantined += 1;
        issues.push({
          sourceKey,
          disposition: "quarantined",
          reason: error instanceof PinnedSourceChangedError ? "source_changed" : "read_failed",
        });
        continue;
      }
      const text = bytes.toString("utf8").normalize("NFKC");
      if (MALFORMED_TEXT.test(text)) {
        filesQuarantined += 1;
        issues.push({ sourceKey, disposition: "quarantined", reason: "malformed_text" });
        continue;
      }
      if ((extension === ".json" || extension === ".jsonl") && extension === ".json") {
        try { JSON.parse(text); }
        catch {
          filesQuarantined += 1;
          issues.push({ sourceKey, disposition: "quarantined", reason: "malformed_text" });
          continue;
        }
      }

      const partition = reusableSourcePartition(text, extension);
      if (partition.safeSegments.length === 0) {
        filesQuarantined += 1;
        issues.push({ sourceKey, disposition: "quarantined", reason: "secret_bearing_source" });
        continue;
      }
      if (partition.secretBearingSegmentsQuarantined > 0) {
        issues.push({
          sourceKey,
          disposition: "quarantined",
          reason: "secret_bearing_segment",
          count: partition.secretBearingSegmentsQuarantined,
        });
      }

      const extractions = partition.safeSegments.map((segment) => ({
        segment,
        extraction: extractFacts(file, segment.text),
      }));
      if (!extractions.some(({ extraction }) => extraction.facts.length > 0)) {
        filesSkipped += 1;
        issues.push({ sourceKey, disposition: "skipped", reason: "no_reusable_semantics" });
        continue;
      }

      let remainingFactBudget = this.#maxFactsPerFile;
      let candidateBudgetExceeded = 0;
      let fileAmbiguousFragments = 0;
      let acceptedKnowledgeUnits = 0;
      let compilerQuarantines = 0;
      let sourceCandidate: { readonly id: string; readonly created: boolean } | undefined;

      for (const { segment, extraction } of extractions) {
        const boundedFacts = extraction.facts.slice(0, remainingFactBudget);
        remainingFactBudget -= boundedFacts.length;
        candidateBudgetExceeded += Math.max(0, extraction.facts.length - boundedFacts.length);
        fileAmbiguousFragments += extraction.ambiguousFragments +
          Math.max(0, extraction.facts.length - boundedFacts.length);
        if (boundedFacts.length === 0) continue;

        semanticFactsParsed += boundedFacts.length;
        const boundedRoles = new Set(boundedFacts.map(({ role }) => role));
        const boundedEdges = extraction.edges.filter(({ sourceRole, targetRole }) =>
          boundedRoles.has(sourceRole) && boundedRoles.has(targetRole));
        const sourceConfidence = Math.min(...boundedFacts.map(({ confidence }) => confidence));
        const knowledgeUnits: readonly (ReusableAttackFactKnowledge | ReusableAttackBundleKnowledge)[] = boundedEdges.length > 0
          ? [{
            kind: "reusable_bundle",
            facts: boundedFacts.map(({ role, nodeType, title, summary, body }) => ({ role, nodeType, title, summary, body })),
            edges: boundedEdges,
          }]
          : boundedFacts.map((extracted) => ({
            kind: "reusable_fact" as const,
            nodeType: extracted.nodeType,
            title: extracted.title,
            summary: extracted.summary,
            body: extracted.body,
          }));

        for (const knowledge of knowledgeUnits) {
          const wholeSourceBinding = `${file.sha256}\0${file.modifiedAt}\0${manifest.engagementKey}`;
          const result = compilerBatch.compile({
            source: {
              privateSourceReference: file.absolutePath,
              privateLabels: [manifest.engagementName],
              sourceClass: "historical",
              // Preserve the prior whole-file identity for safe sources. Mixed
              // files bind each receipt to the independently safe block hash
              // and ordinal while the full source remains private evidence.
              sourceHash: segment.isolatedFromMixedSource
                ? sha256(`${wholeSourceBinding}\0safe-segment\0${segment.ordinal}\0${segment.contentHash}`)
                : sha256(wholeSourceBinding),
              observedAt: file.modifiedAt,
              evidenceCount: 1,
            },
            knowledge,
            confidence: sourceConfidence,
          }, { dryRun });
          if (result.status === "quarantined") {
            compilerQuarantines += 1;
            continue;
          }
          acceptedKnowledgeUnits += 1;
          addKnowledgeDistribution(knowledge, nodeTypeCounts, edgeTypeCounts);
          if (knowledge.kind === "reusable_bundle") {
            const projectedSourceCandidateId = this.#sourceCandidateId(sourceInventory);
            knowledge.edges.forEach(({ edgeType }) => {
              const sourceIds = edgeSourceEvidenceCandidateIds.get(edgeType) ?? new Set<string>();
              sourceIds.add(projectedSourceCandidateId);
              edgeSourceEvidenceCandidateIds.set(edgeType, sourceIds);
            });
          }
          compilerBundlesStaged += 1;
          candidatesCreated += result.candidatesCreated;
          candidatesReused += result.candidatesReused;
          result.candidateIds.forEach((id) => candidateIds.add(id));
          if (!dryRun && result.bundleId && result.provenanceReceiptId) {
            if (!sourceCandidate) {
              sourceCandidate = this.#stageSourceEvidenceCandidate(sourceInventory);
              sourceEvidenceCandidateIds.add(sourceCandidate.id);
              sourceCandidate.created
                ? sourceEvidenceCandidatesCreated += 1
                : sourceEvidenceCandidatesReused += 1;
            }
            sourceBundleLinks += this.#linkSourceEvidenceCandidate(
              result.bundleId,
              result.provenanceReceiptId,
              sourceCandidate.id,
              sourceInventory,
            );
          } else if (dryRun && result.bundleId && result.provenanceReceiptId && !sourceCandidate) {
            const projectedId = this.#sourceCandidateId(sourceInventory);
            const exists = this.#sourceCandidateExists(projectedId);
            sourceEvidenceCandidateIds.add(projectedId);
            sourceEvidenceCandidatesCreated += exists ? 0 : 1;
            sourceEvidenceCandidatesReused += exists ? 1 : 0;
            sourceCandidate = { id: projectedId, created: !exists };
          }
        }
      }

      if (candidateBudgetExceeded > 0) {
        issues.push({
          sourceKey,
          disposition: "ambiguous",
          reason: "candidate_budget_exceeded",
          count: candidateBudgetExceeded,
        });
      }
      const semanticAmbiguities = fileAmbiguousFragments - candidateBudgetExceeded;
      if (semanticAmbiguities > 0) {
        issues.push({ sourceKey, disposition: "ambiguous", reason: "no_reusable_semantics", count: semanticAmbiguities });
      }
      ambiguousFragments += fileAmbiguousFragments;
      if (compilerQuarantines > 0) {
        issues.push({
          sourceKey,
          disposition: "quarantined",
          reason: "secret_bearing_segment",
          count: compilerQuarantines,
        });
      }
      if (acceptedKnowledgeUnits === 0) {
        filesQuarantined += 1;
        continue;
      }
      filesParsed += 1;
      bytesParsed += file.byteSize;
    }
    const nextIndex = startIndex + processedThisRun;
    const partial = nextIndex < eligible.length;
    const compilerBatchResult = compilerBatch.finish();
    return {
      status: partial ? "partial" : "completed",
      dryRun,
      manifestFingerprint,
      filesDiscovered: sourceFiles.length,
      filesParsed,
      filesSkipped,
      filesQuarantined,
      bytesParsed,
      semanticFactsParsed,
      ambiguousFragments,
      compilerBundlesStaged,
      candidatesCreated,
      candidatesReused,
      sourceEvidenceCandidatesCreated,
      sourceEvidenceCandidatesReused,
      sourceBundleLinks,
      compilerReconciliation: compilerBatchResult.reconciliation,
      compilerReconciliationPasses: compilerBatchResult.reconciliationPasses,
      compilerRunsReconciled: compilerBatchResult.compilerRunsReconciled,
      nodeTypeCounts: Object.fromEntries(Object.entries(nodeTypeCounts).sort(([left], [right]) => left.localeCompare(right))),
      edgeTypeCounts: Object.fromEntries(Object.entries(edgeTypeCounts).sort(([left], [right]) => left.localeCompare(right))),
      edgeSourceEvidenceCandidateIds: Object.fromEntries(
        [...edgeSourceEvidenceCandidateIds.entries()]
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([edgeType, sourceIds]) => [edgeType, [...sourceIds].sort()]),
      ),
      ...(partial && lastProcessedSourceKey ? { nextResumeAfterSourceKey: lastProcessedSourceKey } : {}),
      candidateIds: [...candidateIds].sort(),
      sourceEvidenceCandidateIds: [...sourceEvidenceCandidateIds].sort(),
      issues: issues.sort((left, right) => left.sourceKey.localeCompare(right.sourceKey) || left.reason.localeCompare(right.reason)),
    };
  }
}
