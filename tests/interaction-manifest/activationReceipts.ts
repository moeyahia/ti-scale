import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import type {
  InteractionManifest,
  InteractionManifestEntry,
  InteractionReceiptModality,
} from "./schema";

export const INTERACTION_ACTIVATION_SCHEMA_VERSION = 2 as const;
export const INTERACTION_ACTIVATION_SENTINEL = "__control_activation__" as const;
export const INTERACTION_ACTIVATION_ATTACHMENT = "ti-scale-interaction-activation-intents.v2.json" as const;

export type InteractionActivationModality = Exclude<InteractionReceiptModality, "assertion">;
export type InteractionActivationResult = "pass" | "fail";
export type PlaywrightResultStatus = "passed" | "failed" | "timedOut" | "skipped" | "interrupted";

export interface InteractionActivationSourceFile {
  readonly path: string;
  readonly role: "test" | "helper";
  readonly hash: string;
}

export interface InteractionActivationSourceSet {
  readonly hash: string;
  readonly files: readonly InteractionActivationSourceFile[];
}

export interface InteractionActivationIntent {
  readonly schemaVersion: typeof INTERACTION_ACTIVATION_SCHEMA_VERSION;
  readonly manifestEntryId: string;
  readonly controlId: string;
  readonly option: string;
  readonly materialState: string;
  readonly modality: InteractionReceiptModality;
  readonly testId: string;
  readonly playwrightTestId: string;
  readonly playwrightProject: string;
  readonly manifestHash: string;
  readonly sourceHash: string;
  readonly sourceSet: InteractionActivationSourceSet;
  readonly ordinal: number;
}

export interface InteractionActivationIntentEnvelope {
  readonly schemaVersion: typeof INTERACTION_ACTIVATION_SCHEMA_VERSION;
  readonly kind: "interaction-activation-intents";
  readonly intents: readonly InteractionActivationIntent[];
}

export interface InteractionPlaywrightResultRecord {
  readonly recordId: string;
  readonly playwrightTestId: string;
  readonly playwrightProject: string;
  readonly title: string;
  readonly titlePath: readonly string[];
  readonly sourceFile: string;
  readonly sourceLine: number;
  readonly sourceColumn: number;
  readonly sourceHash: string;
  readonly sourceSet: InteractionActivationSourceSet;
  readonly retry: number;
  readonly expectedStatus: PlaywrightResultStatus;
  readonly status: PlaywrightResultStatus;
  readonly declaredTestIds: readonly string[];
}

export interface InteractionActivationReceipt extends InteractionActivationIntent {
  readonly kind: "interaction-activation-receipt";
  readonly receiptKey: string;
  readonly playwrightRecordId: string;
  readonly playwrightTitle: string;
  readonly playwrightTitlePath: readonly string[];
  readonly sourceFile: string;
  readonly sourceLine: number;
  readonly sourceColumn: number;
  readonly retry: number;
  readonly playwrightStatus: PlaywrightResultStatus;
  readonly expectedStatus: PlaywrightResultStatus;
  readonly result: InteractionActivationResult;
  readonly validationErrors: readonly string[];
}

export interface InteractionProjectScope {
  readonly project: string;
  readonly browser: string;
  readonly viewport: string;
  readonly coverageClass: "general" | "brain-renderer";
}

export interface InteractionActivationExpectation {
  readonly manifestEntryId: string;
  readonly controlId: string;
  readonly option: string;
  readonly materialState: string;
  readonly modality: InteractionReceiptModality;
  readonly playwrightProject: string;
  readonly manifestHash: string;
  readonly allowedTestIds: readonly string[];
}

export interface ManifestTestIdBindingReport {
  readonly declaredTestIds: readonly string[];
  readonly boundTestIds: readonly string[];
  readonly missingTestIds: readonly string[];
  readonly undeclaredTestIds: readonly string[];
}

export interface InteractionActivationCoverageReport {
  readonly complete: boolean;
  readonly expectedReceiptCount: number;
  readonly passingReceiptCount: number;
  readonly missingReceiptCount: number;
  readonly missingReceipts: readonly InteractionActivationExpectation[];
  readonly expectedActivationCount: number;
  readonly passingActivationCount: number;
  readonly expectedAssertionCount: number;
  readonly passingAssertionCount: number;
  readonly missingAssertionCount: number;
  readonly missingAssertions: readonly InteractionActivationExpectation[];
  readonly failedReceiptCount: number;
  readonly missingActivationCount: number;
  readonly missingActivations: readonly InteractionActivationExpectation[];
  readonly invalidReceiptErrors: readonly string[];
  readonly duplicateReceiptKeys: readonly string[];
  readonly requiredProjects: readonly string[];
  readonly observedProjects: readonly string[];
  readonly missingRequiredProjects: readonly string[];
  readonly testIdBindings: ManifestTestIdBindingReport;
}

export interface MaterializeReceiptBinding {
  readonly playwrightTestId: string;
  readonly playwrightProject: string;
  readonly title: string;
  readonly titlePath: readonly string[];
  readonly sourceFile: string;
  readonly sourceLine: number;
  readonly sourceColumn: number;
  readonly sourceHash: string;
  readonly sourceSet: InteractionActivationSourceSet;
  readonly retry: number;
  readonly expectedStatus: PlaywrightResultStatus;
  readonly status: PlaywrightResultStatus;
  readonly manifestHash: string;
}

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

export function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function sha256File(path: string): string {
  return sha256Hex(readFileSync(path));
}

export function interactionManifestHash(path: string): string {
  return sha256File(path);
}

function pathIsBelow(root: string, candidate: string): boolean {
  const relativePath = relative(root, candidate);
  return relativePath !== ""
    && relativePath !== ".."
    && !relativePath.startsWith(`..${sep}`)
    && !isAbsolute(relativePath);
}

function canonicalSourcePath(root: string, sourceFile: string, label: string): {
  readonly absolutePath: string;
  readonly relativePath: string;
} {
  const absoluteRoot = realpathSync(resolve(root));
  const unresolvedPath = isAbsolute(sourceFile)
    ? resolve(sourceFile)
    : resolve(absoluteRoot, sourceFile);
  if (!pathIsBelow(absoluteRoot, unresolvedPath)) {
    throw new Error(`${label} must be below interaction activation source root ${absoluteRoot}`);
  }
  if (!existsSync(unresolvedPath)) throw new Error(`${label} does not exist`);
  const metadata = lstatSync(unresolvedPath);
  if (!metadata.isFile()) throw new Error(`${label} must be a regular file`);
  const absolutePath = realpathSync(unresolvedPath);
  if (!pathIsBelow(absoluteRoot, absolutePath)) {
    throw new Error(`${label} resolves outside interaction activation source root ${absoluteRoot}`);
  }
  if (!statSync(absolutePath).isFile()) throw new Error(`${label} must resolve to a regular file`);
  return {
    absolutePath,
    relativePath: relative(absoluteRoot, absolutePath).split(sep).join("/"),
  };
}

export function interactionActivationSourceSetHash(
  files: readonly InteractionActivationSourceFile[],
): string {
  return sha256Hex(JSON.stringify(files.map((file) => [file.path, file.role, file.hash])));
}

function compareCanonicalSourcePaths(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

/**
 * Builds the exact source set that physically implements a receipt. The
 * primary Playwright source is always included; helper sources are explicit,
 * repository-rooted declarations. Real paths are checked so a symlink cannot
 * smuggle an out-of-root implementation into an otherwise valid-looking set.
 */
export function buildInteractionActivationSourceSet(input: {
  readonly sourceRoot: string;
  readonly testSourceFile: string;
  readonly helperSourceFiles?: readonly string[];
}): InteractionActivationSourceSet {
  const primary = canonicalSourcePath(
    input.sourceRoot,
    input.testSourceFile,
    "Interaction activation test source",
  );
  const seen = new Set([primary.relativePath]);
  const files: InteractionActivationSourceFile[] = [{
    path: primary.relativePath,
    role: "test",
    hash: sha256File(primary.absolutePath),
  }];
  for (const [index, helperSourceFile] of (input.helperSourceFiles ?? []).entries()) {
    const helper = canonicalSourcePath(
      input.sourceRoot,
      helperSourceFile,
      `Interaction activation helper source[${index}]`,
    );
    if (seen.has(helper.relativePath)) {
      throw new Error(`Interaction activation source set contains duplicate path ${helper.relativePath}`);
    }
    seen.add(helper.relativePath);
    files.push({
      path: helper.relativePath,
      role: "helper",
      hash: sha256File(helper.absolutePath),
    });
  }
  files.sort((left, right) => compareCanonicalSourcePaths(left.path, right.path));
  return {
    hash: interactionActivationSourceSetHash(files),
    files,
  };
}

export function resolveInteractionActivationOutputPath(
  outputFile: string,
  isolatedRoot = resolve("test-results/results"),
): { readonly isolatedRoot: string; readonly outputFile: string } {
  const root = resolve(isolatedRoot);
  const output = resolve(outputFile);
  const relativePath = relative(root, output);
  if (!relativePath || relativePath === "." || relativePath.startsWith(`..${sep}`) || relativePath === ".." || isAbsolute(relativePath)) {
    throw new Error(`Interaction activation output must be a file below ${root}`);
  }
  return { isolatedRoot: root, outputFile: output };
}

function assertRealDirectory(path: string, label: string): void {
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error(`${label} must be a real directory`);
}

function assertDirectoryChainHasNoSymlink(root: string, directory: string): void {
  const relativePath = relative(root, directory);
  let current = root;
  assertRealDirectory(current, "Interaction activation output root");
  for (const segment of relativePath.split(sep).filter(Boolean)) {
    current = resolve(current, segment);
    assertRealDirectory(current, "Interaction activation output directory");
  }
}

export function writeInteractionActivationArtifactAtomically(input: {
  readonly outputFile: string;
  readonly isolatedRoot?: string;
  readonly body: string;
}): void {
  const paths = resolveInteractionActivationOutputPath(input.outputFile, input.isolatedRoot);
  mkdirSync(paths.isolatedRoot, { recursive: true, mode: 0o700 });
  const outputDirectory = dirname(paths.outputFile);
  mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
  assertDirectoryChainHasNoSymlink(paths.isolatedRoot, outputDirectory);
  if (existsSync(paths.outputFile) && lstatSync(paths.outputFile).isSymbolicLink()) {
    throw new Error("Interaction activation output file must not be a symbolic link");
  }
  const temporaryPath = resolve(
    outputDirectory,
    `.${basename(paths.outputFile)}.${process.pid}.${randomUUID()}.tmp`,
  );
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporaryPath, "wx", 0o600);
    writeFileSync(descriptor, input.body, { encoding: "utf8" });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporaryPath, paths.outputFile);
    const directoryDescriptor = openSync(outputDirectory, "r");
    try {
      fsyncSync(directoryDescriptor);
    } finally {
      closeSync(directoryDescriptor);
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(temporaryPath)) unlinkSync(temporaryPath);
  }
}

function objectRecord(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${path} must be a non-empty string`);
  return value;
}

function exactSha256(value: unknown, path: string): string {
  const hash = exactString(value, path);
  if (!SHA256_PATTERN.test(hash)) throw new Error(`${path} must be a lowercase SHA-256 digest`);
  return hash;
}

function exactInteger(value: unknown, path: string): number {
  if (!Number.isInteger(value) || Number(value) < 0) throw new Error(`${path} must be a non-negative integer`);
  return Number(value);
}

function exactSourcePath(value: unknown, path: string): string {
  const sourcePath = exactString(value, path);
  const segments = sourcePath.split("/");
  if (
    sourcePath.startsWith("/")
    || sourcePath.includes("\\")
    || segments.some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    throw new Error(`${path} must be a canonical repository-relative path`);
  }
  return sourcePath;
}

export function validateInteractionActivationSourceSet(
  value: unknown,
  path = "sourceSet",
): InteractionActivationSourceSet {
  const record = objectRecord(value, path);
  if (!Array.isArray(record.files) || record.files.length === 0) {
    throw new Error(`${path}.files must be a non-empty array`);
  }
  const seen = new Set<string>();
  let previousPath: string | undefined;
  let testSourceCount = 0;
  const files = record.files.map((value, index): InteractionActivationSourceFile => {
    const source = objectRecord(value, `${path}.files[${index}]`);
    const sourcePath = exactSourcePath(source.path, `${path}.files[${index}].path`);
    const role = exactString(source.role, `${path}.files[${index}].role`);
    if (role !== "test" && role !== "helper") {
      throw new Error(`${path}.files[${index}].role must be test or helper`);
    }
    if (seen.has(sourcePath)) throw new Error(`${path}.files contains duplicate path ${sourcePath}`);
    if (previousPath !== undefined && compareCanonicalSourcePaths(previousPath, sourcePath) >= 0) {
      throw new Error(`${path}.files must be sorted by canonical path`);
    }
    seen.add(sourcePath);
    previousPath = sourcePath;
    if (role === "test") testSourceCount += 1;
    return {
      path: sourcePath,
      role,
      hash: exactSha256(source.hash, `${path}.files[${index}].hash`),
    };
  });
  if (testSourceCount !== 1) throw new Error(`${path}.files must contain exactly one test source`);
  const hash = exactSha256(record.hash, `${path}.hash`);
  if (hash !== interactionActivationSourceSetHash(files)) {
    throw new Error(`${path}.hash does not match its canonical source files`);
  }
  return { hash, files };
}

function isValidInteractionActivationSourceSet(value: unknown): boolean {
  try {
    validateInteractionActivationSourceSet(value);
    return true;
  } catch {
    return false;
  }
}

export function validateInteractionActivationIntent(value: unknown, path = "intent"): InteractionActivationIntent {
  const record = objectRecord(value, path);
  if (record.schemaVersion !== INTERACTION_ACTIVATION_SCHEMA_VERSION) {
    throw new Error(`${path}.schemaVersion must be ${INTERACTION_ACTIVATION_SCHEMA_VERSION}`);
  }
  const modality = exactString(record.modality, `${path}.modality`);
  if (modality !== "pointer" && modality !== "keyboard" && modality !== "assertion") {
    throw new Error(`${path}.modality is invalid`);
  }
  const sourceHash = exactSha256(record.sourceHash, `${path}.sourceHash`);
  const sourceSet = validateInteractionActivationSourceSet(record.sourceSet, `${path}.sourceSet`);
  const testSource = sourceSet.files.find((source) => source.role === "test")!;
  if (testSource.hash !== sourceHash) {
    throw new Error(`${path}.sourceHash must match the test source in ${path}.sourceSet`);
  }
  return {
    schemaVersion: INTERACTION_ACTIVATION_SCHEMA_VERSION,
    manifestEntryId: exactString(record.manifestEntryId, `${path}.manifestEntryId`),
    controlId: exactString(record.controlId, `${path}.controlId`),
    option: exactString(record.option, `${path}.option`),
    materialState: exactString(record.materialState, `${path}.materialState`),
    modality,
    testId: exactString(record.testId, `${path}.testId`),
    playwrightTestId: exactString(record.playwrightTestId, `${path}.playwrightTestId`),
    playwrightProject: exactString(record.playwrightProject, `${path}.playwrightProject`),
    manifestHash: exactSha256(record.manifestHash, `${path}.manifestHash`),
    sourceHash,
    sourceSet,
    ordinal: exactInteger(record.ordinal, `${path}.ordinal`),
  };
}

export function validateInteractionActivationIntentEnvelope(value: unknown): InteractionActivationIntentEnvelope {
  const record = objectRecord(value, "activation intent envelope");
  if (record.schemaVersion !== INTERACTION_ACTIVATION_SCHEMA_VERSION) {
    throw new Error(`activation intent envelope.schemaVersion must be ${INTERACTION_ACTIVATION_SCHEMA_VERSION}`);
  }
  if (record.kind !== "interaction-activation-intents") {
    throw new Error("activation intent envelope.kind is invalid");
  }
  if (!Array.isArray(record.intents) || record.intents.length === 0) {
    throw new Error("activation intent envelope.intents must be a non-empty array");
  }
  const intents = record.intents.map((intent, index) => (
    validateInteractionActivationIntent(intent, `activation intent envelope.intents[${index}]`)
  ));
  const sourceSetHash = intents[0]!.sourceSet.hash;
  if (intents.some((intent) => intent.sourceSet.hash !== sourceSetHash)) {
    throw new Error("activation intent envelope intents must share one deterministic source set");
  }
  return {
    schemaVersion: INTERACTION_ACTIVATION_SCHEMA_VERSION,
    kind: "interaction-activation-intents",
    intents,
  };
}

export function manifestOptions(entry: InteractionManifestEntry): readonly string[] {
  return entry.options.length > 0 ? entry.options : [INTERACTION_ACTIVATION_SENTINEL];
}

export function manifestRequiredModalities(entry: InteractionManifestEntry): readonly InteractionReceiptModality[] {
  return entry.requiredModalities ?? ["pointer", "keyboard"];
}

export function createInteractionActivationIntent(input: {
  readonly manifest: InteractionManifest;
  readonly manifestEntryId: string;
  readonly controlId: string;
  readonly option: string;
  readonly materialState: string;
  readonly modality: InteractionReceiptModality;
  readonly testId: string;
  readonly playwrightTestId: string;
  readonly playwrightProject: string;
  readonly manifestHash: string;
  readonly sourceHash: string;
  readonly sourceSet: InteractionActivationSourceSet;
  readonly ordinal: number;
}): InteractionActivationIntent {
  const entry = input.manifest.entries.find((candidate) => candidate.id === input.manifestEntryId);
  if (!entry) throw new Error(`Manifest entry ${input.manifestEntryId} does not exist`);
  if (entry.controlId !== input.controlId) {
    throw new Error(`Manifest entry ${entry.id} belongs to control ${entry.controlId}, not ${input.controlId}`);
  }
  if (!manifestOptions(entry).includes(input.option)) {
    throw new Error(`Manifest entry ${entry.id} does not declare option ${input.option}`);
  }
  if (!manifestRequiredModalities(entry).includes(input.modality)) {
    throw new Error(`Manifest entry ${entry.id} does not require ${input.modality} receipts`);
  }
  if (entry.requiredState !== input.materialState) {
    throw new Error(`Manifest entry ${entry.id} requires material state ${entry.requiredState}`);
  }
  if (!entry.testIds.includes(input.testId)) {
    throw new Error(`Manifest entry ${entry.id} does not declare test ID ${input.testId}`);
  }
  if (!entry.browsers.length || !entry.viewports.length) throw new Error(`Manifest entry ${entry.id} has no project matrix`);
  return validateInteractionActivationIntent({
    schemaVersion: INTERACTION_ACTIVATION_SCHEMA_VERSION,
    manifestEntryId: input.manifestEntryId,
    controlId: input.controlId,
    option: input.option,
    materialState: input.materialState,
    modality: input.modality,
    testId: input.testId,
    playwrightTestId: input.playwrightTestId,
    playwrightProject: input.playwrightProject,
    manifestHash: input.manifestHash,
    sourceHash: input.sourceHash,
    sourceSet: input.sourceSet,
    ordinal: input.ordinal,
  });
}

export function activationReceiptKey(receipt: Pick<
  InteractionActivationReceipt,
  | "manifestEntryId"
  | "controlId"
  | "option"
  | "materialState"
  | "modality"
  | "playwrightProject"
  | "playwrightTestId"
  | "playwrightRecordId"
  | "sourceHash"
  | "sourceSet"
  | "manifestHash"
  | "testId"
  | "ordinal"
>): string {
  return JSON.stringify([
    receipt.manifestEntryId,
    receipt.controlId,
    receipt.option,
    receipt.materialState,
    receipt.modality,
    receipt.playwrightProject,
    receipt.playwrightTestId,
    receipt.playwrightRecordId,
    receipt.sourceHash,
    receipt.sourceSet.hash,
    receipt.manifestHash,
    receipt.testId,
    receipt.ordinal,
  ]);
}

function intentBindingErrors(intent: InteractionActivationIntent, binding: MaterializeReceiptBinding): string[] {
  const errors: string[] = [];
  if (intent.playwrightTestId !== binding.playwrightTestId) errors.push("intent Playwright test ID does not match the actual result record");
  if (intent.playwrightProject !== binding.playwrightProject) errors.push("intent Playwright project does not match the actual result record");
  if (intent.sourceHash !== binding.sourceHash) errors.push("intent source hash does not match the executed test source");
  if (
    intent.sourceSet.hash !== binding.sourceSet.hash
    || JSON.stringify(intent.sourceSet.files) !== JSON.stringify(binding.sourceSet.files)
  ) {
    errors.push("intent source set does not match the executed test and helper sources");
  }
  if (intent.manifestHash !== binding.manifestHash) errors.push("intent manifest hash does not match the audited manifest");
  return errors;
}

export function materializeInteractionActivationReceipts(
  intents: readonly InteractionActivationIntent[],
  binding: MaterializeReceiptBinding,
): { readonly record: InteractionPlaywrightResultRecord; readonly receipts: readonly InteractionActivationReceipt[] } {
  const declaredTestIds = [...new Set(intents.map((intent) => intent.testId))].sort();
  const record: InteractionPlaywrightResultRecord = {
    recordId: `${binding.playwrightTestId}:${binding.retry}`,
    playwrightTestId: binding.playwrightTestId,
    playwrightProject: binding.playwrightProject,
    title: binding.title,
    titlePath: [...binding.titlePath],
    sourceFile: binding.sourceFile,
    sourceLine: binding.sourceLine,
    sourceColumn: binding.sourceColumn,
    sourceHash: binding.sourceHash,
    sourceSet: binding.sourceSet,
    retry: binding.retry,
    expectedStatus: binding.expectedStatus,
    status: binding.status,
    declaredTestIds,
  };
  const receipts = intents.map((intent): InteractionActivationReceipt => {
    const validationErrors = intentBindingErrors(intent, binding);
    const result: InteractionActivationResult = binding.status === "passed"
      && binding.expectedStatus === "passed"
      && binding.retry === 0
      && validationErrors.length === 0
      ? "pass"
      : "fail";
    const unsigned = {
      ...intent,
      kind: "interaction-activation-receipt" as const,
      playwrightRecordId: record.recordId,
      playwrightTitle: binding.title,
      playwrightTitlePath: [...binding.titlePath],
      sourceFile: binding.sourceFile,
      sourceLine: binding.sourceLine,
      sourceColumn: binding.sourceColumn,
      retry: binding.retry,
      playwrightStatus: binding.status,
      expectedStatus: binding.expectedStatus,
      result,
      validationErrors,
    };
    return { ...unsigned, receiptKey: activationReceiptKey(unsigned) };
  });
  return { record, receipts };
}

export function projectScopeForName(project: string): InteractionProjectScope | undefined {
  const exact: Record<string, Omit<InteractionProjectScope, "project">> = {
    "chromium-1440": { browser: "chromium", viewport: "1440x900", coverageClass: "general" },
    "firefox-1440": { browser: "firefox", viewport: "1440x900", coverageClass: "general" },
    "webkit-1440": { browser: "webkit", viewport: "1440x900", coverageClass: "general" },
    "chromium-enterprise-1440": { browser: "chromium-enterprise", viewport: "1440x900", coverageClass: "general" },
    "android-chromium-390": { browser: "android-chromium", viewport: "390x844", coverageClass: "general" },
    "iphone-webkit-390": { browser: "iphone-webkit", viewport: "390x844", coverageClass: "general" },
    "tablet-chromium-768": { browser: "tablet-chromium", viewport: "768x1024", coverageClass: "general" },
    "chromium-360": { browser: "chromium", viewport: "360x800", coverageClass: "general" },
    "chromium-1024": { browser: "chromium", viewport: "1024x768", coverageClass: "general" },
    "chromium-1280": { browser: "chromium", viewport: "1280x800", coverageClass: "general" },
    "chromium-1920": { browser: "chromium", viewport: "1920x1080", coverageClass: "general" },
    "chromium-2560": { browser: "chromium", viewport: "2560x1440", coverageClass: "general" },
    "chromium-200-percent-zoom": { browser: "chromium", viewport: "200%", coverageClass: "general" },
    "brain-renderer-chromium-1440": { browser: "chromium", viewport: "1440x900", coverageClass: "brain-renderer" },
  };
  const scope = exact[project];
  return scope ? { project, ...scope } : undefined;
}

export const RELEASE_INTERACTION_PROJECT_ALLOWLIST = Object.freeze([
  "chromium-1440",
  "firefox-1440",
  "webkit-1440",
  "chromium-enterprise-1440",
  "android-chromium-390",
  "iphone-webkit-390",
  "tablet-chromium-768",
  "chromium-360",
  "chromium-1024",
  "chromium-1280",
  "chromium-1920",
  "chromium-2560",
  "chromium-200-percent-zoom",
  "brain-renderer-chromium-1440",
] as const);

const BRAIN_RENDERER_TEST_IDS = new Set([
  "e2e.brain-graph.atlas-renderer",
  "e2e.brain-graph.atlas-fallback",
]);

function entryAppliesToProject(entry: InteractionManifestEntry, project: InteractionProjectScope): boolean {
  if (!entry.browsers.includes(project.browser) || !entry.viewports.includes(project.viewport)) return false;
  if (project.coverageClass === "brain-renderer") {
    return entry.testIds.some((testId) => BRAIN_RENDERER_TEST_IDS.has(testId));
  }
  return true;
}

export function buildExpectedInteractionActivations(
  manifest: InteractionManifest,
  manifestHash: string,
  projects: readonly InteractionProjectScope[],
): InteractionActivationExpectation[] {
  const expected: InteractionActivationExpectation[] = [];
  for (const project of projects) {
    for (const entry of manifest.entries) {
      if (!entryAppliesToProject(entry, project)) continue;
      for (const option of manifestOptions(entry)) {
        for (const modality of manifestRequiredModalities(entry)) {
          expected.push({
            manifestEntryId: entry.id,
            controlId: entry.controlId,
            option,
            materialState: entry.requiredState,
            modality,
            playwrightProject: project.project,
            manifestHash,
            allowedTestIds: [...entry.testIds],
          });
        }
      }
    }
  }
  return expected;
}

export function bindManifestTestIdsToPlaywrightResults(
  manifest: InteractionManifest,
  records: readonly InteractionPlaywrightResultRecord[],
): ManifestTestIdBindingReport {
  const declared = [...new Set(manifest.entries.flatMap((entry) => entry.testIds))].sort();
  const actual = [...new Set(records.flatMap((record) => record.declaredTestIds))].sort();
  const declaredSet = new Set(declared);
  const actualSet = new Set(actual);
  return {
    declaredTestIds: declared,
    boundTestIds: declared.filter((testId) => actualSet.has(testId)),
    missingTestIds: declared.filter((testId) => !actualSet.has(testId)),
    undeclaredTestIds: actual.filter((testId) => !declaredSet.has(testId)),
  };
}

function activationCoverageKey(value: {
  readonly manifestEntryId: string;
  readonly controlId: string;
  readonly option: string;
  readonly materialState: string;
  readonly modality: InteractionReceiptModality;
  readonly playwrightProject: string;
  readonly manifestHash: string;
}): string {
  return JSON.stringify([
    value.manifestEntryId,
    value.controlId,
    value.option,
    value.materialState,
    value.modality,
    value.playwrightProject,
    value.manifestHash,
  ]);
}

export function validateInteractionActivationCoverage(input: {
  readonly manifest: InteractionManifest;
  readonly manifestHash: string;
  readonly projects: readonly InteractionProjectScope[];
  readonly receipts: readonly InteractionActivationReceipt[];
  readonly records: readonly InteractionPlaywrightResultRecord[];
  readonly requiredProjects: readonly string[];
  readonly maxMissingDetails?: number;
}): InteractionActivationCoverageReport {
  const expected = buildExpectedInteractionActivations(input.manifest, input.manifestHash, input.projects);
  const recordsById = new Map(input.records.map((record) => [record.recordId, record]));
  const invalidReceiptErrors: string[] = [];
  const seenReceiptKeys = new Set<string>();
  const duplicateReceiptKeys = new Set<string>();
  const entryById = new Map(input.manifest.entries.map((entry) => [entry.id, entry]));
  const projectByName = new Map(input.projects.map((project) => [project.project, project]));
  for (const receipt of input.receipts) {
    if (seenReceiptKeys.has(receipt.receiptKey)) duplicateReceiptKeys.add(receipt.receiptKey);
    seenReceiptKeys.add(receipt.receiptKey);
    const record = recordsById.get(receipt.playwrightRecordId);
    const entry = entryById.get(receipt.manifestEntryId);
    const prefix = `${receipt.playwrightProject}/${receipt.playwrightTestId}/${receipt.controlId}/${receipt.option}/${receipt.modality}`;
    if (!record) invalidReceiptErrors.push(`${prefix}: no exact Playwright result record exists`);
    if (!entry) invalidReceiptErrors.push(`${prefix}: manifest entry ${receipt.manifestEntryId} does not exist`);
    if (entry && entry.controlId !== receipt.controlId) invalidReceiptErrors.push(`${prefix}: control ID does not belong to the manifest entry`);
    if (entry && !manifestOptions(entry).includes(receipt.option)) invalidReceiptErrors.push(`${prefix}: option is not declared by the manifest entry`);
    if (entry && !manifestRequiredModalities(entry).includes(receipt.modality)) {
      invalidReceiptErrors.push(`${prefix}: modality is not required by the manifest entry`);
    }
    if (entry && entry.requiredState !== receipt.materialState) invalidReceiptErrors.push(`${prefix}: material state does not match the manifest entry`);
    if (entry && !entry.testIds.includes(receipt.testId)) invalidReceiptErrors.push(`${prefix}: test ID is not declared by the manifest entry`);
    const project = projectByName.get(receipt.playwrightProject);
    if (!project) invalidReceiptErrors.push(`${prefix}: Playwright project is outside the audited project set`);
    if (entry && project && !entryAppliesToProject(entry, project)) {
      invalidReceiptErrors.push(`${prefix}: Playwright project is outside the manifest entry browser/viewport matrix`);
    }
    if (receipt.manifestHash !== input.manifestHash) invalidReceiptErrors.push(`${prefix}: manifest hash is stale`);
    if (!SHA256_PATTERN.test(receipt.sourceHash)) invalidReceiptErrors.push(`${prefix}: source hash is invalid`);
    try {
      validateInteractionActivationSourceSet(receipt.sourceSet, "receipt source set");
    } catch (error) {
      invalidReceiptErrors.push(`${prefix}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (record) {
      if (record.playwrightTestId !== receipt.playwrightTestId || record.playwrightProject !== receipt.playwrightProject) {
        invalidReceiptErrors.push(`${prefix}: receipt identity does not match its Playwright record`);
      }
      if (record.sourceHash !== receipt.sourceHash) invalidReceiptErrors.push(`${prefix}: receipt source hash does not match its Playwright record`);
      if (
        record.sourceSet.hash !== receipt.sourceSet.hash
        || JSON.stringify(record.sourceSet.files) !== JSON.stringify(receipt.sourceSet.files)
      ) {
        invalidReceiptErrors.push(`${prefix}: receipt source set does not match its Playwright record`);
      }
      if (!record.declaredTestIds.includes(receipt.testId)) invalidReceiptErrors.push(`${prefix}: Playwright record does not bind the declared test ID`);
      if (record.status !== receipt.playwrightStatus || record.expectedStatus !== receipt.expectedStatus) {
        invalidReceiptErrors.push(`${prefix}: receipt status does not match its Playwright record`);
      }
    }
    if (receipt.validationErrors.length > 0) {
      invalidReceiptErrors.push(...receipt.validationErrors.map((error) => `${prefix}: ${error}`));
    }
  }
  const structurallyPassingKeys = new Set(input.receipts.flatMap((receipt) => {
    const entry = entryById.get(receipt.manifestEntryId);
    const record = recordsById.get(receipt.playwrightRecordId);
    const project = projectByName.get(receipt.playwrightProject);
    const structurallyValid = receipt.result === "pass"
      && receipt.validationErrors.length === 0
      && receipt.manifestHash === input.manifestHash
      && Boolean(entry)
      && entry?.controlId === receipt.controlId
      && manifestOptions(entry!).includes(receipt.option)
      && manifestRequiredModalities(entry!).includes(receipt.modality)
      && entry?.requiredState === receipt.materialState
      && entry?.testIds.includes(receipt.testId)
      && Boolean(project)
      && entryAppliesToProject(entry!, project!)
      && Boolean(record)
      && record?.playwrightTestId === receipt.playwrightTestId
      && record?.playwrightProject === receipt.playwrightProject
      && record?.sourceHash === receipt.sourceHash
      && isValidInteractionActivationSourceSet(receipt.sourceSet)
      && record?.sourceSet.hash === receipt.sourceSet.hash
      && JSON.stringify(record?.sourceSet.files) === JSON.stringify(receipt.sourceSet.files)
      && record?.declaredTestIds.includes(receipt.testId)
      && record?.status === receipt.playwrightStatus
      && record?.expectedStatus === receipt.expectedStatus;
    return structurallyValid ? [activationCoverageKey(receipt)] : [];
  }));
  const missing = expected.filter((expectation) => !structurallyPassingKeys.has(activationCoverageKey(expectation)));
  const detailLimit = input.maxMissingDetails ?? Number.POSITIVE_INFINITY;
  const expectedActivations = expected.filter((expectation) => expectation.modality !== "assertion");
  const missingActivations = missing.filter((expectation) => expectation.modality !== "assertion");
  const expectedAssertions = expected.filter((expectation) => expectation.modality === "assertion");
  const missingAssertions = missing.filter((expectation) => expectation.modality === "assertion");
  const bindings = bindManifestTestIdsToPlaywrightResults(input.manifest, input.records);
  const observedProjects = [...new Set(input.projects.map((project) => project.project))].sort();
  const requiredProjects = [...new Set(input.requiredProjects)].sort();
  const observedProjectSet = new Set(observedProjects);
  const missingRequiredProjects = requiredProjects.filter((project) => !observedProjectSet.has(project));
  const complete = missing.length === 0
    && invalidReceiptErrors.length === 0
    && duplicateReceiptKeys.size === 0
    && input.receipts.every((receipt) => receipt.result === "pass")
    && missingRequiredProjects.length === 0
    && bindings.missingTestIds.length === 0
    && bindings.undeclaredTestIds.length === 0;
  return {
    complete,
    expectedReceiptCount: expected.length,
    passingReceiptCount: expected.length - missing.length,
    missingReceiptCount: missing.length,
    missingReceipts: missing.slice(0, detailLimit),
    expectedActivationCount: expectedActivations.length,
    passingActivationCount: expectedActivations.length - missingActivations.length,
    expectedAssertionCount: expectedAssertions.length,
    passingAssertionCount: expectedAssertions.length - missingAssertions.length,
    missingAssertionCount: missingAssertions.length,
    missingAssertions: missingAssertions.slice(0, detailLimit),
    failedReceiptCount: input.receipts.filter((receipt) => receipt.result === "fail").length,
    missingActivationCount: missingActivations.length,
    missingActivations: missingActivations.slice(0, detailLimit),
    invalidReceiptErrors,
    duplicateReceiptKeys: [...duplicateReceiptKeys].sort(),
    requiredProjects,
    observedProjects,
    missingRequiredProjects,
    testIdBindings: bindings,
  };
}
