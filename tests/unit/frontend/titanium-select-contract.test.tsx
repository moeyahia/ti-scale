import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { findTitaniumTypeaheadIndex, TitaniumSelect } from "../../../src/design-system/components/TitaniumSelect";

const sourceRoot = new URL("../../../src", import.meta.url).pathname;
const controlsCss = readFileSync(new URL("../../../src/design-system/tokens/titanium-controls.css", import.meta.url), "utf8");
const shellCss = readFileSync(new URL("../../../src/design-system/tokens/ti-scale.css", import.meta.url), "utf8");
const selectSource = readFileSync(new URL("../../../src/design-system/components/TitaniumSelect.tsx", import.meta.url), "utf8");
const missionAssignmentSource = readFileSync(new URL("../../../src/features/missions/MissionAgentModelAssignments.tsx", import.meta.url), "utf8");
const interactionManifest = readFileSync(new URL("../../interaction-manifest.json", import.meta.url), "utf8");

function productionTsxFiles(path: string): string[] {
  return readdirSync(path).flatMap((name) => {
    const item = join(path, name);
    return statSync(item).isDirectory() ? productionTsxFiles(item) : name.endsWith(".tsx") ? [item] : [];
  });
}

describe("Ti-Scale command selector", () => {
  test("keeps canonical form semantics while declaring the application-owned listbox", () => {
    const markup = renderToStaticMarkup(
      <label htmlFor="mission-template">Mission template
        <TitaniumSelect
          id="mission-template"
          name="templateId"
          value="safe"
          required
          data-control-id="mission-template-control"
          onChange={() => undefined}
        >
          <option value="safe">Safe recon</option>
          <option value="deep">Deep assessment</option>
        </TitaniumSelect>
      </label>,
    );

    expect(markup).toContain('<select name="templateId" id="mission-template-form-proxy" class="os-titanium-select__form-proxy"');
    expect(markup).toContain('aria-hidden="true" tabindex="-1"');
    expect(markup).toContain('<button id="mission-template" type="button" role="combobox"');
    expect(markup).toContain('role="combobox" data-control-id="mission-template-control"');
    expect(markup.match(/data-control-id="mission-template-control"/gu)).toHaveLength(1);
    expect(markup).toContain('aria-haspopup="listbox"');
    expect(markup).toContain('aria-expanded="false"');
    expect(markup).toContain('aria-required="true"');
    expect(markup).toContain('aria-controls="mission-template-listbox"');
    expect(markup.match(/required=""/gu)?.length).toBe(1);
    expect(markup).toContain('<option value="safe" selected="">Safe recon</option>');
    expect(markup).toContain('class="os-titanium-select__mechanism"');
    expect(markup).not.toContain('role="listbox"');
  });

  test("exposes deterministic disabled, loading, and error states", () => {
    const markup = renderToStaticMarkup(
      <TitaniumSelect aria-label="Provider" value="" loading error="Provider catalog is unavailable">
        <option value="">Choose provider</option>
      </TitaniumSelect>,
    );
    expect(markup).toContain('data-select-state="loading"');
    expect(markup).toContain('disabled=""');
    expect(markup).toContain('aria-busy="true"');
    expect(markup).toContain('aria-invalid="true"');
    expect(markup).toContain('role="alert"');
    expect(markup).toContain('Provider catalog is unavailable');
  });

  test("keeps multi-word keyboard typeahead deterministic and ignores disabled matches", () => {
    const options = [
      { value: "candidate-disabled", label: "Candidate archived", disabled: true },
      { value: "candidate", label: "Candidate active", disabled: false },
      { value: "confirmed", label: "Confirmed", disabled: false },
      { value: "operator", label: "Operator verified", disabled: false },
    ];
    expect(findTitaniumTypeaheadIndex(options, "candidate a")).toBe(1);
    expect(findTitaniumTypeaheadIndex(options, "OPERATOR V")).toBe(3);
    expect(findTitaniumTypeaheadIndex(options, "missing")).toBe(-1);
  });

  test("routes every production selector through the shared non-native disclosure", () => {
    const files = productionTsxFiles(sourceRoot);
    const rawNativeOwners = files.filter((file) => file.endsWith("TitaniumSelect.tsx") === false && /<select\b/u.test(readFileSync(file, "utf8")));
    const migratedCount = files.reduce((total, file) => total + (readFileSync(file, "utf8").match(/<TitaniumSelect\b/gu)?.length ?? 0), 0);
    expect(rawNativeOwners).toEqual([]);
    expect(missionAssignmentSource.match(/<TitaniumSelect\b/gu)?.length).toBe(6);
    [
      "autonomous-intake-team-model-primary-provider",
      "autonomous-intake-team-model-primary-model",
      "autonomous-intake-team-model-primary-reasoning",
      "autonomous-intake-team-model-fallback-provider",
      "autonomous-intake-team-model-fallback-model",
      "autonomous-intake-team-model-fallback-reasoning",
      "autonomous-branch-model-primary-provider",
      "autonomous-branch-model-primary-model",
      "autonomous-branch-model-primary-reasoning",
      "autonomous-branch-model-fallback-provider",
      "autonomous-branch-model-fallback-model",
      "autonomous-branch-model-fallback-reasoning",
    ].forEach((controlId) => expect(interactionManifest).toContain(controlId));
    expect(migratedCount).toBe(72);
  });

  test("owns a branded portal disclosure without native picker or compositor top-layer dependencies", () => {
    expect(controlsCss).toContain("appearance: none;");
    expect(controlsCss).toContain(".os-titanium-select__form-proxy");
    expect(controlsCss).toContain("pointer-events: none;");
    expect(controlsCss).toContain('.os-titanium-select__listbox[data-top-layer="true"]');
    expect(shellCss).toContain("--os-z-portal-disclosure: calc(var(--os-z-palette) + 1);");
    expect(shellCss).toContain("--os-z-accessibility: calc(var(--os-z-portal-disclosure) + 1);");
    expect(controlsCss).toContain("z-index: var(--os-z-portal-disclosure);");
    expect(shellCss).toContain("z-index: var(--os-z-accessibility);");
    expect(controlsCss).toContain('data-positioning="sheet"');
    expect(controlsCss).not.toContain('data-positioning="anchored"');
    expect(controlsCss).not.toContain("position-try-fallbacks:");
    expect(controlsCss).not.toContain("@keyframes ti-select-deploy");
    expect(selectSource).toContain('import { createPortal } from "react-dom";');
    expect(selectSource).toContain('rootRef.current?.closest<HTMLElement>(".ti-scale")');
    expect(selectSource).toContain("createPortal(listbox, portalHost)");
    expect(selectSource).not.toContain("showPopover");
    expect(selectSource).not.toContain("hidePopover");
    expect(selectSource).not.toContain("popover=");
    expect(selectSource).toContain('event.key === " " && typeaheadRef.current.length === 0');
    expect(selectSource).toContain("findTitaniumTypeaheadIndex(options, query)");
    expect(controlsCss).toContain("@media (hover: hover) and (pointer: fine)");
    expect(controlsCss).toContain('.ti-scale[data-motion-state="active"] .os-card[data-ti-plate]:hover');
    expect(controlsCss).toContain("--ti-plate-keel: polygon(");
    expect(controlsCss).toContain(".os-card__chassis {");
    expect(controlsCss).toContain("clip-path: var(--ti-plate-shape);");
    expect(controlsCss).not.toContain(".os-card {\n  clip-path:");
    expect(controlsCss).toContain("@media (prefers-reduced-motion: reduce)");
    expect(controlsCss).toContain("transform: none !important;");
  });
});
