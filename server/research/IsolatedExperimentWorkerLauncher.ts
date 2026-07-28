import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  lstatSync,
  openSync,
  readFileSync,
  readlinkSync,
  statSync,
} from "node:fs";
import { spawn, type ChildProcess } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { canonicalJson, deepFreeze, hashCanonical, sha256, type JsonValue } from "./canonical";
import type { PreparedLabEnvironment } from "./LabEnvironmentManager";
import type { ResearchReadinessProbeDescriptor } from "./LocalResearchReadinessProbe";
import {
  type ResearchExecutionBindings,
  type ResearchExecutionReceipt,
  ResearchExecutionReceiptKeyring,
  type ResearchResourceLimits,
  type WorkerReceiptSubject,
} from "./ResearchExecutionReceipts";

const MAXIMUM_OUTPUT_BYTES = 64 * 1024;
const HASH = /^[a-f0-9]{64}$/u;

export const ISOLATED_EXPERIMENT_WORKER_SOURCE = String.raw`
import hashlib,json,os,resource,socket,sys
def canonical(value):
  return json.dumps(value,sort_keys=True,separators=(",",":"))
def digest(value):
  return hashlib.sha256(value).hexdigest()
def read_status():
  result={}
  with open("/proc/self/status","r",encoding="utf-8") as source:
    for line in source:
      if ":" in line:
        key,value=line.split(":",1);result[key]=value.strip()
  return result
def namespace(name):
  return os.readlink("/proc/self/ns/"+name)
def fixture_state():
  result=[]
  for base,dirs,files in os.walk("/fixture"):
    dirs.sort()
    for name in sorted(files):
      path=os.path.join(base,name)
      relative=os.path.relpath(path,"/fixture").replace(os.sep,"/")
      if relative==".ti-scale-owned.json":
        continue
      with open(path,"rb") as source:
        result.append([relative,digest(source.read())])
  return digest(canonical(result).encode())
challenge,expected_fixture,launcher_hash,source_hash=sys.argv[1:5]
status=read_status()
network_denied=False
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(0.1)
try:
  network_denied=s.connect_ex(("198.18.0.1",9))!=0
finally:
  s.close()
fixture_read_only=False
try:
  open("/fixture/.write-challenge","wb").close()
except OSError:
  fixture_read_only=True
work_private=False
try:
  path="/work/write-challenge"
  with open(path,"wb") as target: target.write(challenge.encode())
  work_private=open(path,"rb").read()==challenge.encode()
  os.unlink(path)
except OSError:
  work_private=False
sensitive=("TOKEN","PASSWORD","SECRET","PRIVATE_KEY","API_KEY","COOKIE","CREDENTIAL")
credential_environment_empty=not any(any(mark in key.upper() for mark in sensitive) for key in os.environ)
mountinfo=open("/proc/self/mountinfo","rb").read()
stat_tail=open("/proc/self/stat","r",encoding="utf-8").read().rsplit(")",1)[1].split()
limits={
 "addressSpaceBytes":resource.getrlimit(resource.RLIMIT_AS)[0],
 "cpuSeconds":resource.getrlimit(resource.RLIMIT_CPU)[0],
 "maxFileBytes":resource.getrlimit(resource.RLIMIT_FSIZE)[0],
 "maxOpenFiles":resource.getrlimit(resource.RLIMIT_NOFILE)[0],
 "maxProcesses":resource.getrlimit(resource.RLIMIT_NPROC)[0]
}
identity={
 "processId":os.getpid(),
 "processStartTicks":stat_tail[19],
 "userId":os.getuid(),
 "groupId":os.getgid(),
 "namespaceIds":{
   "mount":namespace("mnt"),"network":namespace("net"),
   "pid":namespace("pid"),"user":namespace("user")
 },
 "noNewPrivileges":status.get("NoNewPrivs")=="1",
 "effectiveCapabilities":status.get("CapEff",""),
 "permittedCapabilities":status.get("CapPrm",""),
 "ambientCapabilities":status.get("CapAmb",""),
 "fixtureReadOnly":fixture_read_only,
 "workFilesystemPrivate":work_private,
 "networkConnectDenied":network_denied,
 "credentialEnvironmentEmpty":credential_environment_empty,
 "mountPolicyHash":digest(mountinfo),
 "workerSourceSha256":source_hash,
 "launcherIdentityHash":launcher_hash,
 "labStateHash":fixture_state(),
 "resourceLimits":limits
}
print(canonical({
 "schemaVersion":"ti-scale.isolated-worker-challenge.v1",
 "phase":"challenge",
 "challengeHash":digest(challenge.encode()),
 "expectedFixtureHash":expected_fixture,
 "identity":identity
}),flush=True)
line=sys.stdin.readline()
if not line:
  raise SystemExit(71)
job=json.loads(line)
required=("schemaVersion","admissionId","admissionHash","experimentId","scenarioId","seed","candidate")
if sorted(job.keys())!=sorted(required) or job["schemaVersion"]!="ti-scale.experiment-job.v1":
  raise SystemExit(72)
candidate_hash=digest(canonical(job["candidate"]).encode())
seed_hash=digest(job["seed"].encode())
fixture_hash=fixture_state()
with open("/fixture/scenario.json","r",encoding="utf-8") as source:
  scenario=json.load(source)
track=scenario.get("track","self_test")
if track=="repeated_no_progress_action_reduction":
  limit=job["candidate"]["loopControl"]["maxIdenticalFingerprints"]
  executed=[];prevented=[];previous="";repeated=0
  for index,action in enumerate(scenario["actions"]):
    if action["progress"]:
      previous="";repeated=0;executed.append(index);continue
    repeated=repeated+1 if action["fingerprint"]==previous else 1
    previous=action["fingerprint"]
    (prevented if repeated>limit else executed).append(index)
  decision={"kind":"loop_control","executedActionIndexes":executed,"preventedActionIndexes":prevented}
elif track=="specialist_routing_quality":
  threshold=job["candidate"]["specialistRouting"]["minimumCapabilityScore"]
  assignments=[]
  for task in scenario["tasks"]:
    eligible=[
      item for item in task["candidates"]
      if task["requiredCapability"] in item["capabilities"]
      and item["capabilityScore"]>=threshold
    ]
    eligible.sort(key=lambda item:(-item["capabilityScore"],item["agentId"]))
    assignments.append({"taskId":task["taskId"],"agentId":eligible[0]["agentId"] if eligible else None})
  decision={"kind":"specialist_routing","assignments":assignments}
elif track=="memory_retrieval_precision":
  threshold=job["candidate"]["memoryRetrieval"]["minimumConfidence"]
  selected=sorted([
    item["memoryId"] for item in scenario["candidates"]
    if item["verified"] and item["sameEngagement"] and item["confidence"]>=threshold
  ])
  decision={"kind":"memory_retrieval","selectedMemoryIds":selected}
else:
  decision={"kind":"self_test"}
fixture_integrity=fixture_hash==expected_fixture
event_hash=digest(canonical({
 "experimentId":job["experimentId"],"scenarioId":job["scenarioId"],
 "candidateHash":candidate_hash,"seedHash":seed_hash,"decision":decision
}).encode())
evidence_hash=digest(canonical({
 "fixtureHash":fixture_hash,"admissionHash":job["admissionHash"],
 "workerSourceSha256":source_hash
}).encode())
print(canonical({
 "schemaVersion":"ti-scale.experiment-worker-result.v1",
 "phase":"result",
 "admissionId":job["admissionId"],
 "admissionHash":job["admissionHash"],
 "experimentId":job["experimentId"],
 "scenarioId":job["scenarioId"],
 "candidateHash":candidate_hash,
 "fixtureHash":fixture_hash,
 "fixtureIntegrity":fixture_integrity,
 "decision":decision,
 "eventHash":event_hash,
 "evidenceHash":evidence_hash
}),flush=True)
`;

export function isolatedExperimentWorkerSourceSha256(): string {
  return sha256(ISOLATED_EXPERIMENT_WORKER_SOURCE);
}

export interface LocalBwrapResearchExecutionEnvironment {
  readonly kind: "local_bwrap";
  readonly identityHash: string;
  readonly toolManifestHash: string;
  readonly workerSourceHash: string;
}

interface OpenExecutable {
  readonly descriptor: number;
  readonly sha256: string;
  readonly path: string;
  close(): void;
}

function openReviewedExecutable(input: {
  readonly path: string;
  readonly sha256: string;
}): OpenExecutable {
  const pathMetadata = lstatSync(input.path);
  if (
    pathMetadata.isSymbolicLink()
    || !pathMetadata.isFile()
    || (pathMetadata.mode & 0o022) !== 0
    || (pathMetadata.mode & 0o7000) !== 0
    || (pathMetadata.mode & 0o111) === 0
  ) throw new Error("Research worker executable is unsafe.");
  const descriptor = openSync(
    input.path,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = statSync(`/proc/self/fd/${descriptor}`);
    if (
      opened.dev !== pathMetadata.dev
      || opened.ino !== pathMetadata.ino
      || opened.size !== pathMetadata.size
      || opened.mtimeMs !== pathMetadata.mtimeMs
      || opened.ctimeMs !== pathMetadata.ctimeMs
    ) throw new Error("Research worker executable identity changed.");
    const digest = createHash("sha256")
      .update(readFileSync(descriptor))
      .digest("hex");
    if (digest !== input.sha256) {
      throw new Error("Research worker executable identity does not match its reviewed hash.");
    }
    let closed = false;
    return {
      descriptor,
      sha256: digest,
      path: input.path,
      close(): void {
        if (closed) return;
        closed = true;
        closeSync(descriptor);
      },
    };
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

function currentNamespaceIds(): WorkerReceiptSubject["parentNamespaceIds"] {
  return Object.freeze({
    mount: readlinkSync("/proc/self/ns/mnt"),
    network: readlinkSync("/proc/self/ns/net"),
    pid: readlinkSync("/proc/self/ns/pid"),
    user: readlinkSync("/proc/self/ns/user"),
  });
}

function resourceLimits(
  descriptor: ResearchReadinessProbeDescriptor,
): ResearchResourceLimits {
  return Object.freeze({
    addressSpaceBytes: descriptor.limits.addressSpaceBytes,
    cpuSeconds: descriptor.limits.cpuSeconds,
    maxProcesses: descriptor.limits.maxProcesses,
    maxFileBytes: descriptor.limits.maxFileBytes,
    maxOpenFiles: descriptor.limits.maxOpenFiles,
  });
}

/**
 * Truthful identity for the exact local execution boundary. This is not an
 * OCI/container digest: it binds the reviewed executables, worker source,
 * mount/network policy, and enforced resource limits used by bwrap.
 */
export function researchWorkerExecutionEnvironmentBinding(
  descriptor: ResearchReadinessProbeDescriptor,
): LocalBwrapResearchExecutionEnvironment {
  const sourceHash = isolatedExperimentWorkerSourceSha256();
  const limits = resourceLimits(descriptor);
  const mountPolicy =
    "usr-ro,fixture-ro,work-tmpfs,proc,dev,no-network";
  const identityHash = hashCanonical({
    bwrap: descriptor.isolationExecutable.sha256,
    prlimit: descriptor.resourceLimitExecutable.sha256,
    python: descriptor.evaluatorExecutable.sha256,
    sourceHash,
    limits,
    mountPolicy,
  } as unknown as JsonValue);
  const toolManifestHash = hashCanonical({
    schemaVersion: "ti-scale.local-bwrap-tool-manifest.v1",
    executables: {
      bwrap: descriptor.isolationExecutable.sha256,
      prlimit: descriptor.resourceLimitExecutable.sha256,
      python: descriptor.evaluatorExecutable.sha256,
    },
    workerSourceSha256: sourceHash,
    resourceLimits: limits,
    mountPolicy,
    outboundNetwork: "disabled",
    liveTargetTools: [],
  } as unknown as JsonValue);
  return deepFreeze({
    kind: "local_bwrap",
    identityHash,
    toolManifestHash,
    workerSourceHash: sourceHash,
  });
}

interface WorkerChallengeOutput {
  readonly schemaVersion: "ti-scale.isolated-worker-challenge.v1";
  readonly phase: "challenge";
  readonly challengeHash: string;
  readonly expectedFixtureHash: string;
  readonly identity: {
    readonly processId: number;
    readonly processStartTicks: string;
    readonly userId: number;
    readonly groupId: number;
    readonly namespaceIds: WorkerReceiptSubject["namespaceIds"];
    readonly noNewPrivileges: boolean;
    readonly effectiveCapabilities: string;
    readonly permittedCapabilities: string;
    readonly ambientCapabilities: string;
    readonly fixtureReadOnly: boolean;
    readonly workFilesystemPrivate: boolean;
    readonly networkConnectDenied: boolean;
    readonly credentialEnvironmentEmpty: boolean;
    readonly mountPolicyHash: string;
    readonly workerSourceSha256: string;
    readonly launcherIdentityHash: string;
    readonly labStateHash: string;
    readonly resourceLimits: ResearchResourceLimits;
  };
}

export interface ExperimentWorkerResult {
  readonly schemaVersion: "ti-scale.experiment-worker-result.v1";
  readonly phase: "result";
  readonly admissionId: string;
  readonly admissionHash: string;
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly candidateHash: string;
  readonly fixtureHash: string;
  readonly fixtureIntegrity: boolean;
  readonly decision:
    | {
        readonly kind: "self_test";
      }
    | {
        readonly kind: "loop_control";
        readonly executedActionIndexes: readonly number[];
        readonly preventedActionIndexes: readonly number[];
      }
    | {
        readonly kind: "specialist_routing";
        readonly assignments: readonly {
          readonly taskId: string;
          readonly agentId: string | null;
        }[];
      }
    | {
        readonly kind: "memory_retrieval";
        readonly selectedMemoryIds: readonly string[];
      };
  readonly eventHash: string;
  readonly evidenceHash: string;
}

export interface ExperimentWorkerJob {
  readonly admissionId: string;
  readonly admissionHash: string;
  readonly experimentId: string;
  readonly scenarioId: string;
  readonly seed: string;
  readonly candidate: JsonValue;
}

export interface PreparedExperimentWorker {
  readonly processId: number;
  readonly receipt: ResearchExecutionReceipt<"worker">;
  readonly subject: WorkerReceiptSubject;
  isAlive(): boolean;
  execute(job: ExperimentWorkerJob): Promise<ExperimentWorkerResult>;
  terminate(): Promise<boolean>;
}

interface LineReader {
  next(timeoutMs: number): Promise<string>;
  close(error: Error): void;
}

function lineReader(stream: Readable): LineReader {
  const lines: string[] = [];
  const waiters: Array<{
    readonly resolve: (value: string) => void;
    readonly reject: (error: Error) => void;
    readonly timer: ReturnType<typeof setTimeout>;
  }> = [];
  let buffer = "";
  let bytes = 0;
  let terminal: Error | undefined;
  const flush = (): void => {
    while (lines.length > 0 && waiters.length > 0) {
      const waiter = waiters.shift()!;
      clearTimeout(waiter.timer);
      waiter.resolve(lines.shift()!);
    }
  };
  stream.on("data", (chunk: Buffer) => {
    bytes += chunk.length;
    if (bytes > MAXIMUM_OUTPUT_BYTES) {
      terminal = new Error("Research worker output exceeded its reviewed bound.");
      for (const waiter of waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(terminal);
      }
      return;
    }
    buffer += chunk.toString("utf8");
    let newline = buffer.indexOf("\n");
    while (newline >= 0) {
      lines.push(buffer.slice(0, newline));
      buffer = buffer.slice(newline + 1);
      newline = buffer.indexOf("\n");
    }
    flush();
  });
  return {
    next(timeoutMs): Promise<string> {
      if (lines.length > 0) return Promise.resolve(lines.shift()!);
      if (terminal) return Promise.reject(terminal);
      return new Promise((resolveLine, rejectLine) => {
        const timer = setTimeout(() => {
          const index = waiters.findIndex(({ resolve }) => resolve === resolveLine);
          if (index >= 0) waiters.splice(index, 1);
          rejectLine(new Error("Research worker response timed out."));
        }, timeoutMs);
        timer.unref?.();
        waiters.push({ resolve: resolveLine, reject: rejectLine, timer });
      });
    },
    close(error): void {
      terminal = error;
      for (const waiter of waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(error);
      }
    },
  };
}

function killGroup(child: ChildProcess): void {
  if (child.pid && process.platform !== "win32") {
    try {
      process.kill(-child.pid, "SIGKILL");
      return;
    } catch {
      // Fall through to the exact tracked process.
    }
  }
  try { child.kill("SIGKILL"); } catch { /* already terminal */ }
}

function processGroupGone(processId: number): boolean {
  try {
    process.kill(-processId, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
}

function exactProcessAlive(processId: number, startTicks: string): boolean {
  try {
    return processStartTicksFromStat(
      readFileSync(`/proc/${processId}/stat`, "utf8"),
    ) === startTicks;
  } catch {
    return false;
  }
}

function processStartTicksFromStat(value: string): string {
  const close = value.lastIndexOf(")");
  if (close < 0) return "";
  // Fields after the executable name begin at proc field 3 (state). Start time
  // is proc field 22, therefore index 19 in this tail.
  return value.slice(close + 1).trim().split(/\s+/u)[19] ?? "";
}

function parseWorkerHostProcessId(line: string): number {
  const value = JSON.parse(line) as { readonly "child-pid"?: unknown };
  const processId = value?.["child-pid"];
  if (!Number.isSafeInteger(processId) || Number(processId) < 1) {
    throw new Error("Research worker launcher did not attest its child process.");
  }
  return Number(processId);
}

function exactObjectKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index]);
}

function parseChallenge(
  line: string,
  expected: {
    readonly hostProcessId: number;
    readonly hostProcessStartTicks: string;
    readonly challengeHash: string;
    readonly fixtureHash: string;
    readonly launcherIdentityHash: string;
    readonly parentNamespaces: WorkerReceiptSubject["parentNamespaceIds"];
    readonly sourceHash: string;
    readonly limits: ResearchResourceLimits;
  },
): WorkerReceiptSubject {
  const value = JSON.parse(line) as WorkerChallengeOutput;
  if (
    !value
    || value.schemaVersion !== "ti-scale.isolated-worker-challenge.v1"
    || value.phase !== "challenge"
    || value.challengeHash !== expected.challengeHash
    || value.expectedFixtureHash !== expected.fixtureHash
    || !value.identity
  ) throw new Error("Research worker challenge response is malformed or unbound.");
  const identity = value.identity;
  const failures: string[] = [];
  const require = (condition: boolean, label: string): void => {
    if (!condition) failures.push(label);
  };
  require(
    Number.isSafeInteger(identity.processId) && identity.processId >= 1,
    "namespace_process",
  );
  require(
    identity.processStartTicks === expected.hostProcessStartTicks,
    "process_start",
  );
  require(Number.isSafeInteger(identity.userId), "uid");
  require(Number.isSafeInteger(identity.groupId), "gid");
  require(identity.noNewPrivileges === true, "no_new_privileges");
  require(
    identity.effectiveCapabilities === "0000000000000000",
    "effective_capabilities",
  );
  require(
    identity.permittedCapabilities === "0000000000000000",
    "permitted_capabilities",
  );
  require(
    identity.ambientCapabilities === "0000000000000000",
    "ambient_capabilities",
  );
  require(identity.fixtureReadOnly === true, "fixture_read_only");
  require(identity.workFilesystemPrivate === true, "private_work_filesystem");
  require(identity.networkConnectDenied === true, "network_denial");
  require(
    identity.credentialEnvironmentEmpty === true,
    "credential_environment",
  );
  require(HASH.test(identity.mountPolicyHash), "mount_policy");
  require(identity.workerSourceSha256 === expected.sourceHash, "worker_source");
  require(
    identity.launcherIdentityHash === expected.launcherIdentityHash,
    "launcher_identity",
  );
  require(identity.labStateHash === expected.fixtureHash, "lab_state");
  require(
    canonicalJson(identity.resourceLimits as unknown as JsonValue)
      === canonicalJson(expected.limits as unknown as JsonValue),
    "resource_limits",
  );
  require(
    identity.namespaceIds.network !== expected.parentNamespaces.network,
    "network_namespace",
  );
  require(
    identity.namespaceIds.mount !== expected.parentNamespaces.mount,
    "mount_namespace",
  );
  require(
    identity.namespaceIds.pid !== expected.parentNamespaces.pid,
    "pid_namespace",
  );
  require(
    identity.namespaceIds.user !== expected.parentNamespaces.user,
    "user_namespace",
  );
  if (failures.length > 0) {
    throw new Error(
      `Research worker failed its identity or isolation challenge: ${failures.join(",")}`,
    );
  }
  return deepFreeze({
    processId: expected.hostProcessId,
    namespaceProcessId: identity.processId,
    processStartTicks: identity.processStartTicks,
    userId: identity.userId,
    groupId: identity.groupId,
    namespaceIds: identity.namespaceIds,
    parentNamespaceIds: expected.parentNamespaces,
    noNewPrivileges: true,
    effectiveCapabilities: "0000000000000000",
    permittedCapabilities: "0000000000000000",
    ambientCapabilities: "0000000000000000",
    fixtureReadOnly: true,
    workFilesystemPrivate: true,
    networkNamespaceIsolated: true,
    networkConnectDenied: true,
    credentialEnvironmentEmpty: true,
    mountPolicyHash: identity.mountPolicyHash,
    workerSourceSha256: identity.workerSourceSha256,
    launcherIdentityHash: identity.launcherIdentityHash,
    labStateHash: identity.labStateHash,
    resourceLimits: identity.resourceLimits,
    orphanControl: "pid_namespace_and_process_group",
  });
}

function parseResult(line: string, expected: ExperimentWorkerJob & {
  readonly fixtureHash: string;
}): ExperimentWorkerResult {
  const value = JSON.parse(line) as ExperimentWorkerResult;
  if (
    !value
    || !exactObjectKeys(value as unknown as Record<string, unknown>, [
      "schemaVersion", "phase", "admissionId", "admissionHash",
      "experimentId", "scenarioId", "candidateHash", "fixtureHash",
      "fixtureIntegrity", "decision", "eventHash", "evidenceHash",
    ])
    || value.schemaVersion !== "ti-scale.experiment-worker-result.v1"
    || value.phase !== "result"
    || value.admissionId !== expected.admissionId
    || value.admissionHash !== expected.admissionHash
    || value.experimentId !== expected.experimentId
    || value.scenarioId !== expected.scenarioId
    || value.fixtureHash !== expected.fixtureHash
    || !HASH.test(value.candidateHash)
    || !HASH.test(value.eventHash)
    || !HASH.test(value.evidenceHash)
    || typeof value.fixtureIntegrity !== "boolean"
    || !value.decision
  ) throw new Error("Research worker result is malformed or not bound to its admission.");
  return deepFreeze(value);
}

export interface PrepareWorkerInput extends ResearchExecutionBindings {
  readonly lab: PreparedLabEnvironment;
}

/**
 * Starts one exact, single-use worker process. The challenge and subsequent
 * experiment job use the same PID; no readiness result is projected from a
 * different helper process.
 */
export class IsolatedExperimentWorkerLauncher {
  readonly #descriptor: ResearchReadinessProbeDescriptor;
  readonly #keyring: ResearchExecutionReceiptKeyring;
  readonly #timeoutMs: number;

  constructor(
    descriptor: ResearchReadinessProbeDescriptor,
    keyring: ResearchExecutionReceiptKeyring,
  ) {
    this.#descriptor = structuredClone(descriptor);
    this.#keyring = keyring;
    this.#timeoutMs = descriptor.timeoutMs;
  }

  async prepare(input: PrepareWorkerInput): Promise<PreparedExperimentWorker> {
    if (
      input.lab.resetGeneration !== input.resetGeneration
      || input.lab.receipt.resetGeneration !== input.resetGeneration
      || input.lab.baselineStateHash !== input.lab.receipt.subject.resetStateHash
    ) throw new Error("Research worker lab binding is inconsistent.");
    const labVerification = this.#keyring.verify(input.lab.receipt, {
      kind: "lab",
      experimentId: input.experimentId,
      scenarioId: input.scenarioId,
      benchmarkSnapshotHash: input.benchmarkSnapshotHash,
      evaluatorHash: input.evaluatorHash,
      toolManifestHash: input.toolManifestHash,
      resetGeneration: input.resetGeneration,
    });
    if (!labVerification.valid) {
      throw new Error(`Research worker rejected its lab receipt: ${labVerification.reasons.join(",")}`);
    }

    const executionEnvironment =
      researchWorkerExecutionEnvironmentBinding(this.#descriptor);
    const bwrap = openReviewedExecutable(this.#descriptor.isolationExecutable);
    const prlimit = openReviewedExecutable(
      this.#descriptor.resourceLimitExecutable,
    );
    const python = openReviewedExecutable(this.#descriptor.evaluatorExecutable);
    const parentNamespaces = currentNamespaceIds();
    const sourceHash = isolatedExperimentWorkerSourceSha256();
    const limits = resourceLimits(this.#descriptor);
    const launcherIdentityHash = executionEnvironment.identityHash;
    const challenge = randomBytes(32).toString("hex");
    const challengeHash = sha256(challenge);
    const args = [
      "--unshare-all",
      "--unshare-net",
      "--die-with-parent",
      "--new-session",
      "--as-pid-1",
      "--json-status-fd", "2",
      "--cap-drop", "ALL",
      "--ro-bind", "/usr", "/usr",
      "--symlink", "usr/bin", "/bin",
      "--symlink", "usr/lib", "/lib",
      "--symlink", "usr/lib64", "/lib64",
      "--symlink", "usr/sbin", "/sbin",
      "--dir", "/etc",
      "--dir", "/trusted",
      "--dev", "/dev",
      "--proc", "/proc",
      "--tmpfs", "/tmp",
      "--tmpfs", "/work",
      "--ro-bind", input.lab.workspacePath, "/fixture",
      "--ro-bind-fd", "4", "/trusted/prlimit",
      "--ro-bind-fd", "5", "/trusted/python",
      "--clearenv",
      "--setenv", "HOME", "/tmp",
      "--setenv", "LANG", "C.UTF-8",
      "--setenv", "LC_ALL", "C.UTF-8",
      "--chdir", "/work",
      "--",
      "/trusted/prlimit",
      `--as=${limits.addressSpaceBytes}`,
      `--cpu=${limits.cpuSeconds}`,
      `--nproc=${limits.maxProcesses}`,
      `--fsize=${limits.maxFileBytes}`,
      `--nofile=${limits.maxOpenFiles}`,
      "--",
      "/trusted/python",
      "-I",
      "-S",
      "-c",
      ISOLATED_EXPERIMENT_WORKER_SOURCE,
      challenge,
      input.lab.baselineStateHash,
      launcherIdentityHash,
      sourceHash,
    ];
    let child: ChildProcess;
    try {
      child = spawn("/proc/self/fd/3", args, {
        detached: true,
        shell: false,
        windowsHide: true,
        env: { HOME: "/nonexistent", LANG: "C.UTF-8", LC_ALL: "C.UTF-8" },
        stdio: [
          "pipe",
          "pipe",
          "pipe",
          bwrap.descriptor,
          prlimit.descriptor,
          python.descriptor,
        ],
      });
    } finally {
      bwrap.close();
      prlimit.close();
      python.close();
    }
    const stdin = child.stdin as Writable;
    const stdout = child.stdout as Readable;
    const stderr = child.stderr as Readable;
    const reader = lineReader(stdout);
    const statusReader = lineReader(stderr);
    let stderrText = "";
    let stderrBytes = 0;
    stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stderrBytes <= MAXIMUM_OUTPUT_BYTES) stderrText += chunk.toString("utf8");
      else killGroup(child);
    });
    child.on("close", (code, signal) => {
      const error = new Error(
        `Research worker exited before the expected response (${String(code)}/${String(signal)}): ${stderrText.trim()}`,
      );
      reader.close(error);
      statusReader.close(error);
    });
    child.on("error", (error) => {
      reader.close(error);
      statusReader.close(error);
    });
    let workerHostProcessId = 0;
    let workerHostStartTicks = "";
    const terminate = async (): Promise<boolean> => {
      if (child.exitCode === null && child.signalCode === null) killGroup(child);
      await new Promise<void>((resolveClose) => {
        if (child.exitCode !== null || child.signalCode !== null) {
          resolveClose();
          return;
        }
        const timer = setTimeout(resolveClose, this.#timeoutMs);
        timer.unref?.();
        child.once("close", () => {
          clearTimeout(timer);
          resolveClose();
        });
      });
      const deadline = Date.now() + this.#timeoutMs;
      do {
        const launcherGone = child.pid ? processGroupGone(child.pid) : true;
        const workerGone = workerHostProcessId < 1
          || !exactProcessAlive(workerHostProcessId, workerHostStartTicks);
        if (launcherGone && workerGone) return true;
        await new Promise<void>((resolve) => setTimeout(resolve, 10));
      } while (Date.now() < deadline);
      return false;
    };

    try {
      workerHostProcessId = parseWorkerHostProcessId(
        await statusReader.next(this.#timeoutMs),
      );
      workerHostStartTicks = processStartTicksFromStat(
        readFileSync(`/proc/${workerHostProcessId}/stat`, "utf8"),
      );
      const subject = parseChallenge(
        await reader.next(this.#timeoutMs),
        {
          hostProcessId: workerHostProcessId,
          hostProcessStartTicks: workerHostStartTicks,
          challengeHash,
          fixtureHash: input.lab.baselineStateHash,
          launcherIdentityHash,
          parentNamespaces,
          sourceHash,
          limits,
        },
      );
      const subjectIdentityHash = hashCanonical(subject as unknown as JsonValue);
      const evidenceHash = hashCanonical({
        challengeHash,
        subjectIdentityHash,
        labReceiptId: input.lab.receipt.receiptId,
        launcherIdentityHash,
      } as unknown as JsonValue);
      const receipt = this.#keyring.create("worker", {
        experimentId: input.experimentId,
        scenarioId: input.scenarioId,
        benchmarkSnapshotHash: input.benchmarkSnapshotHash,
        evaluatorHash: input.evaluatorHash,
        toolManifestHash: input.toolManifestHash,
        resetGeneration: input.resetGeneration,
        challengeHash,
        subjectIdentityHash,
        evidenceHash,
        controls: {
          liveClientTargetsAllowed: false,
          productionSecretsMounted: false,
          productionMutationAllowed: false,
          publicProviderExecutionAllowed: false,
          quotaBound: true,
          resetVerified: false,
        },
        subject,
      });
      let executed = false;
      return {
        processId: subject.processId,
        receipt,
        subject,
        isAlive: () =>
          child.exitCode === null
          && child.signalCode === null
          && !child.killed
          && exactProcessAlive(workerHostProcessId, workerHostStartTicks),
        execute: async (job): Promise<ExperimentWorkerResult> => {
          if (executed) throw new Error("Research experiment worker is single-use.");
          if (
            child.exitCode !== null
            || child.signalCode !== null
            || child.killed
            || !exactProcessAlive(workerHostProcessId, workerHostStartTicks)
          ) {
            throw new Error("Research experiment worker is no longer alive.");
          }
          executed = true;
          stdin.write(`${canonicalJson({
            schemaVersion: "ti-scale.experiment-job.v1",
            admissionId: job.admissionId,
            admissionHash: job.admissionHash,
            experimentId: job.experimentId,
            scenarioId: job.scenarioId,
            seed: job.seed,
            candidate: job.candidate,
          } as unknown as JsonValue)}\n`);
          stdin.end();
          return parseResult(
            await reader.next(this.#timeoutMs),
            { ...job, fixtureHash: input.lab.baselineStateHash },
          );
        },
        terminate,
      };
    } catch (error) {
      await terminate();
      throw error;
    }
  }
}
