import type {
  FullConfig,
  FullResult,
  Reporter,
  Suite,
  TestCase,
  TestResult,
} from "@playwright/test/reporter";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  INTERACTION_ACTIVATION_ATTACHMENT,
  INTERACTION_ACTIVATION_SCHEMA_VERSION,
  buildInteractionActivationSourceSet,
  interactionManifestHash,
  materializeInteractionActivationReceipts,
  projectScopeForName,
  validateInteractionActivationCoverage,
  validateInteractionActivationIntentEnvelope,
  writeInteractionActivationArtifactAtomically,
  type InteractionActivationCoverageReport,
  type InteractionActivationReceipt,
  type InteractionPlaywrightResultRecord,
  type InteractionProjectScope,
  type PlaywrightResultStatus,
} from "../../interaction-manifest/activationReceipts";
import { validateInteractionManifest, type InteractionManifest } from "../../interaction-manifest/schema";
import { declaredInteractionActivationHelperSources } from "./interactionActivationSourceDeclarations";

interface InteractionActivationReporterOptions {
  readonly outputFile?: string;
  readonly manifestPath?: string;
  readonly enforce?: boolean;
  readonly requiredProjects?: readonly string[];
}

export interface InteractionActivationRunReport {
  readonly schemaVersion: typeof INTERACTION_ACTIVATION_SCHEMA_VERSION;
  readonly kind: "interaction-activation-run-report";
  readonly generatedAt: string;
  readonly playwrightRunStatus: FullResult["status"];
  readonly interactionGateStatus: "passed" | "failed";
  readonly enforced: boolean;
  readonly manifestPath: string;
  readonly manifestHash: string;
  readonly projects: readonly InteractionProjectScope[];
  readonly unknownProjects: readonly string[];
  readonly testRecords: readonly InteractionPlaywrightResultRecord[];
  readonly receipts: readonly InteractionActivationReceipt[];
  readonly reporterErrors: readonly string[];
  readonly coverage: InteractionActivationCoverageReport;
}

function attachmentBody(attachment: TestResult["attachments"][number]): Buffer {
  if (attachment.body) return attachment.body;
  if (attachment.path) return readFileSync(attachment.path);
  throw new Error(`Attachment ${attachment.name} has neither a body nor a path`);
}

function expectedStatus(status: TestCase["expectedStatus"]): PlaywrightResultStatus {
  return status;
}

export default class InteractionActivationReporter implements Reporter {
  readonly #sourceRoot = resolve(import.meta.dirname, "../../..");
  readonly #manifestPath: string;
  readonly #outputFile: string;
  readonly #enforce: boolean;
  readonly #manifest: InteractionManifest;
  readonly #manifestHash: string;
  readonly #requiredProjects: readonly string[];
  readonly #records: InteractionPlaywrightResultRecord[] = [];
  readonly #receipts: InteractionActivationReceipt[] = [];
  readonly #errors: string[] = [];
  #projects: InteractionProjectScope[] = [];
  #unknownProjects: string[] = [];

  constructor(options: InteractionActivationReporterOptions = {}) {
    this.#manifestPath = resolve(options.manifestPath ?? "tests/interaction-manifest.json");
    this.#outputFile = resolve(options.outputFile ?? "test-results/results/interaction-activation-receipts.json");
    this.#enforce = options.enforce ?? process.env.TI_SCALE_E2E_ENFORCE_ACTIVATION_RECEIPTS === "1";
    if (!options.requiredProjects || options.requiredProjects.length === 0) {
      throw new Error("Interaction activation reporter requires an explicit non-empty release project allowlist");
    }
    this.#requiredProjects = [...new Set(options.requiredProjects)];
    const invalidRequiredProjects = this.#requiredProjects.filter((project) => !projectScopeForName(project));
    if (invalidRequiredProjects.length > 0) {
      throw new Error(`Interaction activation reporter has unknown required projects: ${invalidRequiredProjects.join(", ")}`);
    }
    this.#manifest = validateInteractionManifest(JSON.parse(readFileSync(this.#manifestPath, "utf8")) as unknown);
    this.#manifestHash = interactionManifestHash(this.#manifestPath);
  }

  printsToStdio(): boolean {
    return false;
  }

  onBegin(_config: FullConfig, suite: Suite): void {
    const names = [...new Set(suite.suites.filter((candidate) => candidate.type === "project").map((candidate) => candidate.title))];
    this.#projects = names.flatMap((name) => {
      const scope = projectScopeForName(name);
      return scope ? [scope] : [];
    });
    this.#unknownProjects = names.filter((name) => !projectScopeForName(name));
    if (this.#unknownProjects.length > 0) {
      this.#errors.push(`No interaction-manifest browser/viewport mapping exists for projects: ${this.#unknownProjects.join(", ")}`);
    }
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    const attachments = result.attachments.filter((attachment) => attachment.name === INTERACTION_ACTIVATION_ATTACHMENT);
    if (attachments.length === 0) return;
    if (attachments.length !== 1) {
      this.#errors.push(`${test.id}:${result.retry} emitted ${attachments.length} activation intent attachments; exactly one is allowed`);
      return;
    }
    try {
      const envelope = validateInteractionActivationIntentEnvelope(JSON.parse(attachmentBody(attachments[0]!).toString("utf8")) as unknown);
      const project = test.parent.project()?.name;
      if (!project) throw new Error("actual Playwright result has no project identity");
      const sourceSet = buildInteractionActivationSourceSet({
        sourceRoot: this.#sourceRoot,
        testSourceFile: test.location.file,
        helperSourceFiles: declaredInteractionActivationHelperSources({
          sourceRoot: this.#sourceRoot,
          testSourceFile: test.location.file,
        }),
      });
      const sourceHash = sourceSet.files.find((source) => source.role === "test")!.hash;
      const materialized = materializeInteractionActivationReceipts(envelope.intents, {
        playwrightTestId: test.id,
        playwrightProject: project,
        title: test.title,
        titlePath: test.titlePath(),
        sourceFile: test.location.file,
        sourceLine: test.location.line,
        sourceColumn: test.location.column,
        sourceHash,
        sourceSet,
        retry: result.retry,
        expectedStatus: expectedStatus(test.expectedStatus),
        status: result.status,
        manifestHash: this.#manifestHash,
      });
      this.#records.push(materialized.record);
      this.#receipts.push(...materialized.receipts);
    } catch (error) {
      this.#errors.push(`${test.id}:${result.retry}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async onEnd(result: FullResult): Promise<{ status: FullResult["status"] } | undefined> {
    if (process.env.TI_SCALE_E2E_DISCOVERY_ONLY === "1") return undefined;
    const coverage = validateInteractionActivationCoverage({
      manifest: this.#manifest,
      manifestHash: this.#manifestHash,
      projects: this.#projects,
      receipts: this.#receipts,
      records: this.#records,
      requiredProjects: this.#requiredProjects,
      maxMissingDetails: 500,
    });
    const interactionGateFailed = !coverage.complete || this.#errors.length > 0;
    const report: InteractionActivationRunReport = {
      schemaVersion: INTERACTION_ACTIVATION_SCHEMA_VERSION,
      kind: "interaction-activation-run-report",
      generatedAt: new Date().toISOString(),
      playwrightRunStatus: result.status,
      interactionGateStatus: interactionGateFailed ? "failed" : "passed",
      enforced: this.#enforce,
      manifestPath: this.#manifestPath,
      manifestHash: this.#manifestHash,
      projects: this.#projects,
      unknownProjects: this.#unknownProjects,
      testRecords: this.#records,
      receipts: this.#receipts,
      reporterErrors: this.#errors,
      coverage,
    };
    writeInteractionActivationArtifactAtomically({
      outputFile: this.#outputFile,
      body: `${JSON.stringify(report, null, 2)}\n`,
    });
    if (this.#enforce && interactionGateFailed) return { status: "failed" };
    return undefined;
  }
}
