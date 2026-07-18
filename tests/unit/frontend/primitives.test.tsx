import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ErrorPanel, ProgressBar } from "../../../src/design-system/components/Primitives";

describe("shared recovery controls", () => {
  test("renders ErrorPanel retry as a non-submit button inside form surfaces", () => {
    const markup = renderToStaticMarkup(
      <form>
        <ErrorPanel error={new Error("A bounded operation failed")} onRetry={() => undefined} />
      </form>,
    );

    expect(markup).toContain('<button class="os-button os-button--secondary " type="button">Try again</button>');
    expect(markup).not.toContain('type="submit">Try again</button>');
  });

  test("renders measured and indeterminate progress with permitted ARIA progressbar semantics", () => {
    const measured = renderToStaticMarkup(<ProgressBar label="Autonomous mission progress" value={0.55} />);
    expect(measured).toContain('role="progressbar"');
    expect(measured).toContain('aria-label="Autonomous mission progress"');
    expect(measured).toContain('aria-valuemin="0"');
    expect(measured).toContain('aria-valuemax="100"');
    expect(measured).toContain('aria-valuenow="55"');
    expect(measured).toContain('aria-valuetext="55% complete"');
    expect(measured).toContain('style="width:55%"');

    const indeterminate = renderToStaticMarkup(<ProgressBar label="Unmeasured mission progress" value={null} />);
    expect(indeterminate).toContain('role="progressbar"');
    expect(indeterminate).toContain('aria-valuetext="Not measured"');
    expect(indeterminate).not.toContain("aria-valuenow");
  });
});
