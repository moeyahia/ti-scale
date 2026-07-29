import type { TestInfo } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  INTERACTION_ACTIVATION_ATTACHMENT,
  INTERACTION_ACTIVATION_SCHEMA_VERSION,
  buildInteractionActivationSourceSet,
  createInteractionActivationIntent,
  interactionManifestHash,
  type InteractionActivationIntent,
  type InteractionActivationIntentEnvelope,
  type InteractionActivationModality,
} from "../../interaction-manifest/activationReceipts";
import { validateInteractionManifest } from "../../interaction-manifest/schema";
import { declaredInteractionActivationHelperSources } from "./interactionActivationSourceDeclarations";

const MANIFEST_PATH = resolve(import.meta.dirname, "../../interaction-manifest.json");
const SOURCE_ROOT = resolve(import.meta.dirname, "../../..");
const manifest = validateInteractionManifest(JSON.parse(readFileSync(MANIFEST_PATH, "utf8")) as unknown);

export interface InteractionActivationInput {
  readonly manifestEntryId: string;
  readonly controlId: string;
  readonly option: string;
  readonly materialState: string;
  readonly modality: InteractionActivationModality;
  readonly testId: string;
}

export type InteractionGuardAssertionInput = Omit<InteractionActivationInput, "modality">;

export interface InteractionActivationRecorder {
  /**
   * Runs one physical browser action and records it only after the action has
   * resolved. Playwright's reporter later binds the intent to the actual test
   * result, project, retry count, manifest bytes, and source bytes.
   */
  activate<T>(input: InteractionActivationInput, action: () => Promise<T>): Promise<T>;

  /**
   * Records one source-bound disabled/blocked guard assertion after its
   * browser assertions resolve. This is deliberately separate from activate:
   * no click, hover, key press, or other fake activation is performed.
   */
  assertGuard<T>(input: InteractionGuardAssertionInput, assertion: () => Promise<T>): Promise<T>;
}

export function createInteractionActivationRecorder(testInfo: TestInfo): {
  readonly recorder: InteractionActivationRecorder;
  readonly attach: () => Promise<void>;
} {
  const intents: InteractionActivationIntent[] = [];
  const manifestHash = interactionManifestHash(MANIFEST_PATH);
  const sourceSet = buildInteractionActivationSourceSet({
    sourceRoot: SOURCE_ROOT,
    testSourceFile: testInfo.file,
    helperSourceFiles: declaredInteractionActivationHelperSources({
      sourceRoot: SOURCE_ROOT,
      testSourceFile: testInfo.file,
    }),
  });
  const sourceHash = sourceSet.files.find((source) => source.role === "test")!.hash;
  const recordIntent = (
    input: InteractionGuardAssertionInput & { readonly modality: InteractionActivationIntent["modality"] },
  ): void => {
    intents.push(createInteractionActivationIntent({
      manifest,
      ...input,
      playwrightTestId: testInfo.testId,
      playwrightProject: testInfo.project.name,
      manifestHash,
      sourceHash,
      sourceSet,
      ordinal: intents.length,
    }));
  };
  const recorder: InteractionActivationRecorder = {
    async activate<T>(input: InteractionActivationInput, action: () => Promise<T>): Promise<T> {
      const result = await action();
      recordIntent(input);
      return result;
    },
    async assertGuard<T>(input: InteractionGuardAssertionInput, assertion: () => Promise<T>): Promise<T> {
      const result = await assertion();
      recordIntent({ ...input, modality: "assertion" });
      return result;
    },
  };
  return {
    recorder,
    async attach(): Promise<void> {
      if (intents.length === 0) return;
      const envelope: InteractionActivationIntentEnvelope = {
        schemaVersion: INTERACTION_ACTIVATION_SCHEMA_VERSION,
        kind: "interaction-activation-intents",
        intents,
      };
      await testInfo.attach(INTERACTION_ACTIVATION_ATTACHMENT, {
        body: Buffer.from(JSON.stringify(envelope)),
        contentType: "application/vnd.ti-scale.interaction-activation-intents+json;version=2",
      });
    },
  };
}
