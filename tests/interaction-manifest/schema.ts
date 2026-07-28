export const INTERACTION_MANIFEST_NAMESPACE = "ti-scale" as const;

export type AccessibleRole =
  | "application"
  | "button"
  | "link"
  | "checkbox"
  | "radio"
  | "combobox"
  | "listbox"
  | "textbox"
  | "option"
  | "tab"
  | "menuitem"
  | "spinbutton"
  | "slider"
  | "region";

export type NativeControlLocator = "native-date-input" | "native-summary";

export type InteractionReceiptModality = "pointer" | "keyboard" | "assertion";

export type InteractionAccessible = {
  readonly name: string;
  readonly match: "exact" | "regex";
} & (
  | { readonly role: AccessibleRole; readonly locator?: never }
  | { readonly role?: never; readonly locator: NativeControlLocator }
);

export interface InteractionManifestEntry {
  readonly id: string;
  readonly route: string;
  readonly surface: string;
  readonly requiredState: string;
  readonly controlId: string;
  readonly accessible: InteractionAccessible;
  readonly controlType: string;
  readonly requiredModalities?: readonly InteractionReceiptModality[];
  readonly options: readonly string[];
  readonly keyboardAction: string;
  readonly pointerAction: string;
  readonly expectedStateTransition: string;
  readonly expectedApiOrEventSideEffect: string | null;
  readonly states: {
    readonly loading: string;
    readonly disabled: string;
    readonly error: string;
  };
  readonly classification: "read-only" | "reversible" | "destructive";
  readonly screenshotsRequired: readonly string[];
  readonly browsers: readonly string[];
  readonly viewports: readonly string[];
  readonly testIds: readonly string[];
}

export interface InteractionManifest {
  readonly schemaVersion: 1;
  readonly application: "TI-SCALE // COMMAND INTELLIGENCE";
  readonly namespace: typeof INTERACTION_MANIFEST_NAMESPACE;
  readonly scope: string;
  readonly entries: readonly InteractionManifestEntry[];
  readonly knownGaps: readonly string[];
}

const roles = new Set<AccessibleRole>([
  "application", "button", "link", "checkbox", "radio", "combobox", "listbox", "textbox", "option", "tab", "menuitem", "spinbutton", "slider", "region",
]);
const nativeControlLocators = new Set<NativeControlLocator>(["native-date-input", "native-summary"]);
const classifications = new Set(["read-only", "reversible", "destructive"]);
const matches = new Set(["exact", "regex"]);

function requiredModalitiesAreValid(value: unknown): value is InteractionReceiptModality[] {
  return Array.isArray(value)
    && (
      (value.length === 2 && value[0] === "pointer" && value[1] === "keyboard")
      || (value.length === 1 && value[0] === "assertion")
    );
}

function record(value: unknown, path: string, errors: string[]): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    errors.push(`${path} must be an object`);
    return undefined;
  }
  return value as Record<string, unknown>;
}

function nonEmpty(value: unknown, path: string, errors: string[]): value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    errors.push(`${path} must be a non-empty string`);
    return false;
  }
  return true;
}

function stringArray(value: unknown, path: string, errors: string[], allowEmpty = true): value is string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.some((item) => typeof item !== "string" || !item.trim())) {
    errors.push(`${path} must be ${allowEmpty ? "an" : "a non-empty"} array of non-empty strings`);
    return false;
  }
  return true;
}

export function validateInteractionManifest(value: unknown): InteractionManifest {
  const errors: string[] = [];
  const root = record(value, "manifest", errors);
  if (!root) throw new Error(errors.join("\n"));
  if (root.schemaVersion !== 1) errors.push("manifest.schemaVersion must be 1");
  if (root.application !== "TI-SCALE // COMMAND INTELLIGENCE") errors.push("manifest.application is not the V2 product identity");
  if (root.namespace !== INTERACTION_MANIFEST_NAMESPACE) errors.push(`manifest.namespace must be ${INTERACTION_MANIFEST_NAMESPACE}`);
  nonEmpty(root.scope, "manifest.scope", errors);
  if (stringArray(root.knownGaps, "manifest.knownGaps", errors)) {
    const normalizedGaps = root.knownGaps.map((gap) => gap.trim());
    if (new Set(normalizedGaps).size !== normalizedGaps.length) {
      errors.push("manifest.knownGaps must not contain duplicate gaps");
    }
  }
  if (!Array.isArray(root.entries) || root.entries.length === 0) {
    errors.push("manifest.entries must be a non-empty array");
  } else {
    const ids = new Set<string>();
    const controlIds = new Set<string>();
    root.entries.forEach((candidate, index) => {
      const path = `manifest.entries[${index}]`;
      const entry = record(candidate, path, errors);
      if (!entry) return;
      if (nonEmpty(entry.id, `${path}.id`, errors)) {
        if (!/^[a-z0-9][a-z0-9._-]+$/u.test(entry.id)) errors.push(`${path}.id has an invalid format`);
        if (ids.has(entry.id)) errors.push(`${path}.id duplicates ${entry.id}`);
        ids.add(entry.id);
      }
      if (nonEmpty(entry.controlId, `${path}.controlId`, errors)) {
        if (controlIds.has(entry.controlId)) errors.push(`${path}.controlId duplicates ${entry.controlId}`);
        controlIds.add(entry.controlId);
      }
      if (nonEmpty(entry.route, `${path}.route`, errors) && !entry.route.startsWith("/")) errors.push(`${path}.route must be internal`);
      nonEmpty(entry.surface, `${path}.surface`, errors);
      nonEmpty(entry.requiredState, `${path}.requiredState`, errors);
      nonEmpty(entry.controlType, `${path}.controlType`, errors);
      if (entry.requiredModalities !== undefined && !requiredModalitiesAreValid(entry.requiredModalities)) {
        errors.push(`${path}.requiredModalities must be exactly ["pointer", "keyboard"] or ["assertion"]`);
      }
      if (
        entry.controlType === "disabled-launch-guard"
        && (!requiredModalitiesAreValid(entry.requiredModalities) || entry.requiredModalities[0] !== "assertion")
      ) {
        errors.push(`${path}.controlType disabled-launch-guard requires requiredModalities ["assertion"]`);
      }
      nonEmpty(entry.keyboardAction, `${path}.keyboardAction`, errors);
      nonEmpty(entry.pointerAction, `${path}.pointerAction`, errors);
      nonEmpty(entry.expectedStateTransition, `${path}.expectedStateTransition`, errors);
      if (entry.expectedApiOrEventSideEffect !== null) nonEmpty(entry.expectedApiOrEventSideEffect, `${path}.expectedApiOrEventSideEffect`, errors);
      stringArray(entry.options, `${path}.options`, errors);
      if (stringArray(entry.screenshotsRequired, `${path}.screenshotsRequired`, errors)) {
        const screenshotIds = new Set<string>();
        entry.screenshotsRequired.forEach((screenshotId) => {
          if (!/^visual\.[a-z0-9][a-z0-9.-]+$/u.test(screenshotId)) {
            errors.push(`${path}.screenshotsRequired contains invalid visual baseline ID ${screenshotId}`);
          }
          if (screenshotIds.has(screenshotId)) {
            errors.push(`${path}.screenshotsRequired duplicates ${screenshotId}`);
          }
          screenshotIds.add(screenshotId);
        });
      }
      stringArray(entry.browsers, `${path}.browsers`, errors, false);
      stringArray(entry.viewports, `${path}.viewports`, errors, false);
      if (stringArray(entry.testIds, `${path}.testIds`, errors, false)) {
        entry.testIds.forEach((testId) => { if (!testId.startsWith("e2e.")) errors.push(`${path}.testIds contains non-E2E ID ${testId}`); });
      }
      if (!classifications.has(String(entry.classification))) errors.push(`${path}.classification is invalid`);
      const accessible = record(entry.accessible, `${path}.accessible`, errors);
      if (accessible) {
        const hasRole = Object.prototype.hasOwnProperty.call(accessible, "role");
        const hasLocator = Object.prototype.hasOwnProperty.call(accessible, "locator");
        if (hasRole === hasLocator) {
          errors.push(`${path}.accessible must declare exactly one role or native locator`);
        } else if (hasRole && !roles.has(accessible.role as AccessibleRole)) {
          errors.push(`${path}.accessible.role is invalid`);
        } else if (hasLocator && !nativeControlLocators.has(accessible.locator as NativeControlLocator)) {
          errors.push(`${path}.accessible.locator is invalid`);
        }
        if (nonEmpty(accessible.name, `${path}.accessible.name`, errors) && accessible.match === "regex") {
          try { new RegExp(accessible.name); } catch { errors.push(`${path}.accessible.name is not a valid regular expression`); }
        }
        if (!matches.has(String(accessible.match))) errors.push(`${path}.accessible.match is invalid`);
      }
      const states = record(entry.states, `${path}.states`, errors);
      if (states) {
        nonEmpty(states.loading, `${path}.states.loading`, errors);
        nonEmpty(states.disabled, `${path}.states.disabled`, errors);
        nonEmpty(states.error, `${path}.states.error`, errors);
      }
    });
  }
  if (errors.length) throw new Error(`Invalid interaction manifest:\n${errors.join("\n")}`);
  return value as InteractionManifest;
}

export function interactionAccessibleLocator(accessible: InteractionAccessible): AccessibleRole | NativeControlLocator {
  return accessible.locator ?? accessible.role;
}
