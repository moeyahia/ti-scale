import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryProvider } from "../../../src/data/cache/QueryProvider";
import { MissionEvidencePanel } from "../../../src/features/missions/MissionWorkspace";

function renderEvidence(missionId: string, runId?: string): string {
  return renderToStaticMarkup(
    <QueryProvider>
      <MissionEvidencePanel missionId={missionId} runId={runId} />
    </QueryProvider>,
  );
}

describe("Mission workspace operational truth integration", () => {
  test("scopes the four-stage Evidence experience to the selected run", () => {
    const markup = renderEvidence("mission-integration", "run-integration");

    expect(markup).toContain('data-mission-id="mission-integration"');
    expect(markup).toContain('data-run-id="run-integration"');
    expect(markup).toContain('data-evidence-scope="selected-run"');
    expect(markup).toContain('aria-label="Operational truth"');
    expect(markup.match(/role="tab"/g)).toHaveLength(4);
    expect(markup).toContain("Logs");
    expect(markup).toContain("Observations");
    expect(markup).toContain("Candidates");
    expect(markup).toContain("Verified evidence");
    expect(markup).toContain("Raw output is not evidence");
  });

  test("uses an explicit mission-wide scope when no run is selected", () => {
    const markup = renderEvidence("mission-without-run");

    expect(markup).toContain('data-mission-id="mission-without-run"');
    expect(markup).not.toContain("data-run-id=");
    expect(markup).toContain('data-evidence-scope="all-mission-runs"');
    expect(markup).toContain("Loading engagement logs");
    expect(markup).not.toContain("No evidence retained");
  });
});
