import { readFileSync } from "node:fs";
import {
  expect,
  type Locator,
  type Page,
  type Request,
  type Response,
  type Route,
} from "./playwright";
import { validateInteractionManifest } from "../../interaction-manifest/schema";
import type {
  InteractionActivationInput,
  InteractionActivationRecorder,
  InteractionGuardAssertionInput,
} from "./interactionActivationFixture";
import {
  readTitaniumOptions,
  selectTitaniumOption,
  type TitaniumOptionEntry,
} from "./titaniumSelect";

export const AUTONOMOUS_INTAKE_ROUTE = "/missions/new/autonomous";
export const INTERACTION_ACTIVATION_SENTINEL = "__control_activation__" as const;

export type IntakeActivationModality = "pointer" | "keyboard";

export interface IntakeReceiptContext {
  readonly recorder: InteractionActivationRecorder;
  readonly testId: string;
}

export interface IntakeApiProxy {
  setBaseUrl(baseUrl: string): void;
  dispose(): Promise<void>;
}

export interface IntakeRequestRecord {
  readonly method: string;
  readonly pathname: string;
  readonly search: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: unknown;
}

export interface IntakeRequestLedger {
  readonly records: readonly IntakeRequestRecord[];
  count(method: string, pathname: string): number;
  matching(method: string, pathname: string): readonly IntakeRequestRecord[];
  dispose(): void;
}

export interface IntakeAdvanceResult {
  readonly resolved: Response;
  readonly preflight?: Response;
}

const manifest = validateInteractionManifest(
  JSON.parse(
    readFileSync(
      new URL("../../interaction-manifest.json", import.meta.url),
      "utf8",
    ),
  ) as unknown,
);

export function autonomousIntakeGroup(page: Page, name: string): Locator {
  return page.getByRole("group", { name, exact: true });
}

export function autonomousIntakeManifestEntry(id: string) {
  const entry = manifest.entries.find((candidate) => candidate.id === id);
  if (!entry) throw new Error(`Autonomous intake manifest entry ${id} is missing`);
  return entry;
}

export function autonomousIntakeManifestOptions(id: string): readonly string[] {
  return autonomousIntakeManifestEntry(id).options;
}

function declaredOption(id: string, option?: string): string {
  const entry = autonomousIntakeManifestEntry(id);
  const represented = entry.options.length > 0
    ? entry.options
    : [INTERACTION_ACTIVATION_SENTINEL];
  const selected = option ?? represented[0];
  if (!selected || !represented.includes(selected)) {
    throw new Error(
      `Autonomous intake manifest entry ${id} does not declare ${option ?? "<default>"}`,
    );
  }
  return selected;
}

function activationInput(
  context: IntakeReceiptContext,
  id: string,
  option: string | undefined,
  modality: IntakeActivationModality,
): InteractionActivationInput {
  const entry = autonomousIntakeManifestEntry(id);
  if (!entry.testIds.includes(context.testId)) {
    throw new Error(
      `Autonomous intake manifest entry ${id} does not declare ${context.testId}`,
    );
  }
  return {
    manifestEntryId: id,
    controlId: entry.controlId,
    option: declaredOption(id, option),
    materialState: entry.requiredState,
    modality,
    testId: context.testId,
  };
}

function guardInput(
  context: IntakeReceiptContext,
  id: string,
  option?: string,
): InteractionGuardAssertionInput {
  const entry = autonomousIntakeManifestEntry(id);
  if (!entry.testIds.includes(context.testId)) {
    throw new Error(
      `Autonomous intake manifest entry ${id} does not declare ${context.testId}`,
    );
  }
  return {
    manifestEntryId: id,
    controlId: entry.controlId,
    option: declaredOption(id, option),
    materialState: entry.requiredState,
    testId: context.testId,
  };
}

export function activateAutonomousIntake<T>(
  context: IntakeReceiptContext,
  id: string,
  option: string | undefined,
  modality: IntakeActivationModality,
  action: () => Promise<T>,
): Promise<T> {
  return context.recorder.activate(
    activationInput(context, id, option, modality),
    action,
  );
}

export function assertAutonomousIntakeGuard<T>(
  context: IntakeReceiptContext,
  id: string,
  option: string | undefined,
  assertion: () => Promise<T>,
): Promise<T> {
  return context.recorder.assertGuard(guardInput(context, id, option), assertion);
}

export function autonomousTitaniumSelect(
  root: Page | Locator,
  name: string | RegExp,
): Locator {
  return root.getByRole("combobox", {
    name,
    exact: typeof name === "string",
  });
}

export function autonomousTitaniumFormProxy(control: Locator): Locator {
  return control
    .locator("xpath=..")
    .locator("select.os-titanium-select__form-proxy");
}

export async function autonomousTitaniumOptions(
  control: Locator,
): Promise<readonly TitaniumOptionEntry[]> {
  const options = await readTitaniumOptions(control);
  expect(
    options.length,
    "A Titanium intake selector must expose at least one represented option",
  ).toBeGreaterThan(0);
  expect(
    options.every(({ label, value }) => label.length > 0 && value.length > 0),
    "Every Titanium intake option must expose a label and canonical value",
  ).toBe(true);
  return options;
}

export async function chooseAutonomousTitaniumOption(
  control: Locator,
  value: string,
  modality: IntakeActivationModality,
): Promise<void> {
  await selectTitaniumOption(control, value, modality);
  await expect(control).toBeFocused();
  await expect(autonomousTitaniumFormProxy(control)).toHaveValue(value);
}

export async function installIntakeApiProxy(
  page: Page,
  initialBaseUrl: string,
): Promise<IntakeApiProxy> {
  let baseUrl = initialBaseUrl;
  const pattern = "**/api/v2/**";
  const handler = async (requestRoute: Route): Promise<void> => {
    const original = new URL(requestRoute.request().url());
    if (
      original.pathname.startsWith("/api/v2/auth/")
      || original.pathname.startsWith("/api/v2/notifications")
      || original.pathname === "/api/v2/events/stream"
    ) {
      await requestRoute.continue();
      return;
    }
    const target = new URL(`${original.pathname}${original.search}`, baseUrl);
    const response = await requestRoute.fetch({
      url: target.href,
      timeout: 30_000,
    });
    await requestRoute.fulfill({ response });
  };
  await page.route(pattern, handler);
  return {
    setBaseUrl(nextBaseUrl: string): void {
      baseUrl = nextBaseUrl;
    },
    async dispose(): Promise<void> {
      if (page.isClosed()) return;
      await page.unroute(pattern, handler);
    },
  };
}

export function createIntakeRequestLedger(page: Page): IntakeRequestLedger {
  const records: IntakeRequestRecord[] = [];
  const listener = (request: Request): void => {
    const url = new URL(request.url());
    if (!url.pathname.startsWith("/api/v2/")) return;
    let body: unknown;
    try {
      body = request.postData() === null ? undefined : request.postDataJSON();
    } catch {
      body = request.postData();
    }
    records.push(Object.freeze({
      method: request.method(),
      pathname: url.pathname,
      search: url.search,
      headers: Object.freeze({ ...request.headers() }),
      body,
    }));
  };
  page.on("request", listener);
  return {
    records,
    count(method: string, pathname: string): number {
      return records.filter(
        (record) => record.method === method && record.pathname === pathname,
      ).length;
    },
    matching(method: string, pathname: string): readonly IntakeRequestRecord[] {
      return records.filter(
        (record) => record.method === method && record.pathname === pathname,
      );
    },
    dispose(): void {
      page.off("request", listener);
    },
  };
}

async function activateElement(
  locator: Locator,
  modality: IntakeActivationModality,
): Promise<void> {
  if (modality === "pointer") {
    await locator.click();
    return;
  }
  await locator.focus();
  await locator.press("Enter");
}

export async function exerciseNativeDisclosure(
  details: Locator,
  context: IntakeReceiptContext,
  manifestEntryId: string,
): Promise<void> {
  const summary = details.locator(":scope > summary");
  await expect(summary).toBeVisible();
  for (const modality of ["pointer", "keyboard"] as const) {
    if ((await details.getAttribute("open")) !== null) {
      await activateElement(summary, modality);
      await expect(details).not.toHaveAttribute("open", "");
    }
    await activateAutonomousIntake(
      context,
      manifestEntryId,
      "Open",
      modality,
      async () => {
        await activateElement(summary, modality);
        await expect(details).toHaveAttribute("open", "");
      },
    );
    await activateAutonomousIntake(
      context,
      manifestEntryId,
      "Close",
      modality,
      async () => {
        await activateElement(summary, modality);
        await expect(details).not.toHaveAttribute("open", "");
      },
    );
  }
}

export async function fillAutonomousIntakeText(
  control: Locator,
  value: string,
  context: IntakeReceiptContext,
  manifestEntryId: string,
): Promise<void> {
  await activateAutonomousIntake(
    context,
    manifestEntryId,
    undefined,
    "pointer",
    async () => {
      await control.click();
      await control.fill(value);
      await expect(control).toHaveValue(value);
    },
  );
  await control.clear();
  await activateAutonomousIntake(
    context,
    manifestEntryId,
    undefined,
    "keyboard",
    async () => {
      await control.focus();
      await control.page().keyboard.insertText(value);
      await expect(control).toHaveValue(value);
    },
  );
}

export async function setAutonomousIntakeCheckbox(
  control: Locator,
  checked: boolean,
  context: IntakeReceiptContext,
  manifestEntryId: string,
  option: string,
  modality: IntakeActivationModality,
): Promise<void> {
  if (await control.isChecked() === checked) {
    if (modality === "pointer") await control.click();
    else {
      await control.focus();
      await control.press("Space");
    }
  }
  await activateAutonomousIntake(
    context,
    manifestEntryId,
    option,
    modality,
    async () => {
      if (modality === "pointer") await control.click();
      else {
        await control.focus();
        await control.press("Space");
      }
      await expect(control).toBeChecked({ checked });
    },
  );
}

export async function activateIntakeStepper(
  page: Page,
  stepNumber: number,
  label: string,
  context: IntakeReceiptContext,
): Promise<void> {
  const control = page.getByRole("button", {
    name: new RegExp(`^${stepNumber}\\s*${label}$`, "u"),
  });
  await expect(control).toBeEnabled();
  for (const modality of ["pointer", "keyboard"] as const) {
    await activateAutonomousIntake(
      context,
      "autonomous-intake.navigation.stepper",
      label,
      modality,
      async () => {
        await activateElement(control, modality);
        await expect(control.locator("xpath=..")).toHaveAttribute(
          "aria-current",
          "step",
        );
      },
    );
  }
}

export async function advanceAutonomousIntake(
  page: Page,
  nextGroup: string,
  options: {
    readonly context?: IntakeReceiptContext;
    readonly manifestOption?: string;
    readonly modality?: IntakeActivationModality;
    readonly expectPreflight?: boolean;
  } = {},
): Promise<IntakeAdvanceResult> {
  const resolvedPromise = page.waitForResponse(
    (response) =>
      response.url().endsWith("/api/v2/registries/intake/resolve")
      && response.request().method() === "POST",
  );
  const preflightPromise = options.expectPreflight
    ? page.waitForResponse(
      (response) =>
        response.url().endsWith("/api/v2/missions/autonomous/preflight")
        && response.request().method() === "POST",
    )
    : undefined;
  const button = page.getByRole("button", { name: "Continue", exact: true });
  const action = async (): Promise<void> => {
    await activateElement(button, options.modality ?? "pointer");
    await expect(autonomousIntakeGroup(page, nextGroup)).toBeVisible();
  };
  if (options.context && options.manifestOption && options.modality) {
    await activateAutonomousIntake(
      options.context,
      "autonomous-intake.navigation.continue",
      options.manifestOption,
      options.modality,
      action,
    );
  } else {
    await action();
  }
  const resolved = await resolvedPromise;
  expect(resolved.status(), await resolved.text()).toBe(200);
  const preflight = preflightPromise ? await preflightPromise : undefined;
  if (preflight) expect(preflight.status(), await preflight.text()).toBe(200);
  return { resolved, ...(preflight ? { preflight } : {}) };
}

export async function returnAutonomousIntake(
  page: Page,
  previousGroup: string,
  context: IntakeReceiptContext,
  manifestOption: string,
  modality: IntakeActivationModality,
): Promise<void> {
  const button = page.getByRole("button", { name: "Back", exact: true });
  await activateAutonomousIntake(
    context,
    "autonomous-intake.navigation.back-button",
    manifestOption,
    modality,
    async () => {
      await activateElement(button, modality);
      await expect(autonomousIntakeGroup(page, previousGroup)).toBeVisible();
    },
  );
}
