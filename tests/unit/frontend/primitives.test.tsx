import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import {
  Card,
  ErrorPanel,
  ProgressBar,
  resolveTitaniumPlateSeed,
  resolveTitaniumPlateVariant,
  titaniumPlateVariants,
} from "../../../src/design-system/components/Primitives";

describe("shared recovery controls", () => {
  test("renders ErrorPanel retry as a non-submit button inside form surfaces", () => {
    const markup = renderToStaticMarkup(
      <form>
        <ErrorPanel
          error={new Error("A bounded operation failed")}
          retryControlId="agent-model-conflict-retry"
          onRetry={() => undefined}
        />
      </form>,
    );

    expect(markup).toContain('<button class="os-button os-button--secondary " data-ti-actuator="secondary" type="button" data-control-id="agent-model-conflict-retry">');
    expect(markup).toContain('<span class="os-button__label">Try again</span>');
    expect(markup).toContain('<span class="os-button__mechanism" aria-hidden="true"><i></i><i></i><i></i></span>');
    expect(markup).not.toContain('type="submit"');
  });

  test("renders measured and indeterminate progress with permitted ARIA progressbar semantics", () => {
    const measured = renderToStaticMarkup(<ProgressBar label="Autonomous mission progress" value={0.55} />);
    expect(measured).toContain('aria-label="Autonomous mission progress"');
    expect(measured).toContain('aria-valuetext="55% complete"');
    expect(measured).toContain('max="100"');
    expect(measured).toContain('value="55"');
    expect(measured).not.toContain("style=");

    const indeterminate = renderToStaticMarkup(<ProgressBar label="Unmeasured mission progress" value={null} />);
    expect(indeterminate).toContain('aria-valuetext="Not measured"');
    expect(indeterminate).not.toContain("value=");
  });

  test("renders a deterministic, nonsemantic titanium chassis without clipping card content", () => {
    const seed = "mission-readiness-primary";
    expect(resolveTitaniumPlateVariant(seed)).toBe(resolveTitaniumPlateVariant(seed));
    expect(resolveTitaniumPlateSeed({ className: "brain-conflicts", fallbackId: "react-a" }))
      .toBe(resolveTitaniumPlateSeed({ className: "brain-conflicts", fallbackId: "react-b" }));
    expect(resolveTitaniumPlateSeed({ fallbackId: "react-a" }))
      .not.toBe(resolveTitaniumPlateSeed({ fallbackId: "react-b" }));
    expect(titaniumPlateVariants).toEqual(["keel", "aero", "prism", "truss"]);

    const markup = renderToStaticMarkup(
      <Card data-ti-plate="prism" aria-label="Mission readiness module">
        <button type="button">Inspect readiness</button>
      </Card>,
    );

    expect(markup).toContain('data-ti-plate="prism"');
    expect(markup).toContain('data-ti-chassis="module" aria-hidden="true"');
    expect(markup).toContain('class="os-card__facet os-card__facet--leading"');
    expect(markup).toContain('class="os-card__facet os-card__facet--trailing"');
    expect(markup).toContain('class="os-card__fastener"');
    expect(markup).toContain('class="os-card__specular-seam"');
    expect(markup).toContain('<button type="button">Inspect readiness</button>');
    expect(markup).not.toContain("style=");
  });
});
