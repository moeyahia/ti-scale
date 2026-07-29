import { expect, type Locator } from "./playwright";

export type TitaniumOptionSelector = string | Readonly<{
  readonly value?: string;
  readonly label?: string;
}>;

export interface TitaniumOptionEntry {
  readonly value: string;
  readonly label: string;
  readonly disabled: boolean;
  readonly selected: boolean;
}

interface RenderedTitaniumOption extends TitaniumOptionEntry {
  readonly id: string;
}

/** Resolves either the visible trigger or its inert native form proxy. */
export async function asTitaniumCombobox(controlOrProxy: Locator): Promise<Locator> {
  // Locator.evaluate() has no action timeout of its own. Prove attachment
  // first so an accessible-name or render-contract regression fails at the
  // normal assertion bound instead of consuming the enclosing test timeout.
  await expect(controlOrProxy).toBeAttached();
  const tagName = await controlOrProxy.evaluate((element) => element.tagName.toLocaleLowerCase());
  const control = tagName === "select"
    ? controlOrProxy.locator("xpath=..").getByRole("combobox")
    : controlOrProxy.and(controlOrProxy.page().locator('[role="combobox"]'));
  await expect(control).toBeVisible();
  await expect(control).toHaveAttribute("role", "combobox");
  return control;
}

async function openResolvedTitaniumSelect(
  control: Locator,
  input: "keyboard" | "pointer" = "keyboard",
): Promise<Locator> {
  const disclosure = await control.evaluate((element) => ({
    expanded: element.getAttribute("aria-expanded") === "true",
    listboxId: element.getAttribute("aria-controls"),
  }));
  if (!disclosure.expanded) {
    if (input === "pointer") {
      await control.click();
    } else {
      await control.focus();
      await control.press("Enter");
    }
  }
  await expect(control).toHaveAttribute("aria-expanded", "true");
  const listboxId = disclosure.listboxId;
  expect(listboxId, "The Ti-Scale selector must own an accessible application listbox").toBeTruthy();
  const listbox = control.page().locator(`[role="listbox"][id=${JSON.stringify(listboxId)}]`);
  await expect(listbox).toBeVisible();
  return listbox;
}

export async function openTitaniumSelect(controlOrProxy: Locator): Promise<Locator> {
  return openResolvedTitaniumSelect(await asTitaniumCombobox(controlOrProxy));
}

async function renderedOptions(listbox: Locator): Promise<readonly RenderedTitaniumOption[]> {
  return listbox.getByRole("option").evaluateAll((options) => options.map((option) => ({
    id: option.id,
    value: option.getAttribute("data-select-value") ?? "",
    label: option.getAttribute("aria-label") ?? option.textContent?.trim() ?? "",
    disabled: option.getAttribute("aria-disabled") === "true" || (option as HTMLButtonElement).disabled,
    selected: option.getAttribute("aria-selected") === "true",
  })));
}

export async function readTitaniumOptions(controlOrProxy: Locator): Promise<readonly TitaniumOptionEntry[]> {
  const control = await asTitaniumCombobox(controlOrProxy);
  const listbox = await openResolvedTitaniumSelect(control);
  const entries = await renderedOptions(listbox);
  await control.press("Escape");
  await expect(control).toHaveAttribute("aria-expanded", "false");
  await expect(control).toBeFocused();
  return entries;
}

function selectedEntry(entries: readonly RenderedTitaniumOption[], selector: TitaniumOptionSelector): RenderedTitaniumOption | undefined {
  if (typeof selector === "string") return entries.find((entry) => entry.value === selector);
  if (selector.value !== undefined) return entries.find((entry) => entry.value === selector.value);
  if (selector.label !== undefined) return entries.find((entry) => entry.label === selector.label);
  return undefined;
}

function shortestUniquePrefix(entries: readonly RenderedTitaniumOption[], target: RenderedTitaniumOption): string | undefined {
  for (let length = 1; length <= target.label.length; length += 1) {
    const prefix = target.label.slice(0, length);
    const normalized = prefix.toLocaleLowerCase();
    const matches = entries.filter((entry) => (
      !entry.disabled && entry.label.toLocaleLowerCase().startsWith(normalized)
    ));
    if (matches.length === 1 && matches[0]?.id === target.id) return prefix;
  }
  return undefined;
}

function optionLocator(listbox: Locator, selector: TitaniumOptionSelector): Locator {
  if (typeof selector === "string") {
    return listbox.locator(`[role="option"][data-select-value=${JSON.stringify(selector)}]`);
  }
  if (selector.value !== undefined) {
    return listbox.locator(`[role="option"][data-select-value=${JSON.stringify(selector.value)}]`);
  }
  if (selector.label !== undefined) {
    return listbox.getByRole("option", { name: selector.label, exact: true });
  }
  throw new Error("A Ti-Scale option selector requires an exact value or label");
}

export async function selectTitaniumOption(
  controlOrProxy: Locator,
  selector: TitaniumOptionSelector,
  input: "keyboard" | "pointer" = "pointer",
): Promise<string> {
  const control = await asTitaniumCombobox(controlOrProxy);
  const listbox = await openResolvedTitaniumSelect(control, input);
  const option = optionLocator(listbox, selector);
  const entries = await renderedOptions(listbox);
  const target = selectedEntry(entries, selector);
  await expect(option).toHaveCount(1);
  await expect(option).toBeEnabled();
  expect(target, "The selected Ti-Scale option must exist in the application listbox").toBeDefined();
  expect(target?.disabled, "The selected Ti-Scale option must remain enabled").toBe(false);
  const value = target?.value ?? "";
  const label = target?.label ?? "";
  expect(label, "Every application-owned selector option must expose an accessible label").not.toBe("");

  if (input === "pointer") {
    await option.click();
  } else {
    const prefix = target ? shortestUniquePrefix(entries, target) : undefined;
    // Long dynamic labels often become unique only inside an appended stable
    // identifier. Typing that entire identifier can legitimately cross the
    // selector's bounded typeahead-reset window, so reserve typeahead for a
    // short human-facing prefix and use the asserted arrow walk otherwise.
    if (prefix && prefix.length <= 12) {
      await control.pressSequentially(prefix);
    } else {
      const enabledEntries = entries.filter((entry) => !entry.disabled);
      const targetOffset = enabledEntries.findIndex((entry) => entry.id === target?.id);
      expect(targetOffset, `Ti-Scale option ${value || "<empty>"} must be keyboard reachable`).toBeGreaterThanOrEqual(0);
      await control.press("Home");
      await expect(control).toHaveAttribute("aria-activedescendant", enabledEntries[0]?.id ?? "");
      for (let offset = 0; offset < targetOffset; offset += 1) {
        await control.press("ArrowDown");
        await expect(control).toHaveAttribute("aria-activedescendant", enabledEntries[offset + 1]?.id ?? "");
      }
    }
    await expect(option).toHaveClass(/is-active/u);
    await expect(control).toHaveAttribute("aria-activedescendant", target?.id ?? "");
    await control.press("Enter");
  }

  await expect(control).toHaveAttribute("aria-expanded", "false");
  await expect(control.locator("xpath=..").locator("select.os-titanium-select__form-proxy")).toHaveValue(value);
  await expect(control).toContainText(label);
  await expect(control).toBeFocused();
  return value;
}

/**
 * Attempts a rendered disabled option with a physical pointer, or proves
 * keyboard navigation skips it, without changing the canonical form value.
 */
export async function verifyTitaniumOptionDisabled(
  controlOrProxy: Locator,
  selector: TitaniumOptionSelector,
  input: "keyboard" | "pointer",
): Promise<void> {
  const control = await asTitaniumCombobox(controlOrProxy);
  const formProxy = control.locator("xpath=..").locator("select.os-titanium-select__form-proxy");
  const valueBefore = await formProxy.inputValue();
  const listbox = await openResolvedTitaniumSelect(control, input);
  const entries = await renderedOptions(listbox);
  const target = selectedEntry(entries, selector);
  const option = optionLocator(listbox, selector);

  await expect(option).toHaveCount(1);
  await expect(option).toBeDisabled();
  expect(target, "The disabled Ti-Scale option must exist in the application listbox").toBeDefined();
  expect(target?.disabled, "The audited Ti-Scale option must remain disabled").toBe(true);
  expect(target?.label, "Every disabled selector option must expose an accessible label").not.toBe("");

  if (input === "pointer") {
    await option.scrollIntoViewIfNeeded();
    const box = await option.boundingBox();
    expect(box, "The disabled Ti-Scale option must have a physical pointer target").not.toBeNull();
    const x = (box?.x ?? 0) + ((box?.width ?? 0) / 2);
    const y = (box?.y ?? 0) + ((box?.height ?? 0) / 2);
    expect(
      await option.evaluate((element, point) => {
        const hit = document.elementFromPoint(point.x, point.y);
        return hit === element || (hit !== null && element.contains(hit));
      }, { x, y }),
      "The physical pointer coordinate must resolve to the disabled option",
    ).toBe(true);
    await control.page().mouse.click(x, y);
  } else {
    await control.press("Home");
    await expect(control).not.toHaveAttribute("aria-activedescendant", target?.id ?? "");
    for (let offset = 0; offset < entries.length; offset += 1) {
      await control.press("ArrowDown");
      await expect(control).not.toHaveAttribute("aria-activedescendant", target?.id ?? "");
      await expect(formProxy).toHaveValue(valueBefore);
    }
  }

  await expect(listbox).toBeVisible();
  await expect(control).toHaveAttribute("aria-expanded", "true");
  await expect(control).not.toHaveAttribute("aria-activedescendant", target?.id ?? "");
  await expect(formProxy).toHaveValue(valueBefore);
  await control.press("Escape");
  await expect(control).toHaveAttribute("aria-expanded", "false");
  await expect(control).toBeFocused();
}
