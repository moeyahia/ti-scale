import { describe, expect, test } from "bun:test";
import {
  productRosterDescription,
  productRosterReadinessSummary,
  productRosterSource,
  runtimeBindingSummaries,
} from "../../../src/features/agents/agentRuntimeBindings";

describe("agent runtime binding presentation", () => {
  test("reads, reconciles, deduplicates, and orders canonical runtime binding receipts", () => {
    const agent = {
      version: "fallback-version",
      configuration: {
        schemaVersion: "ti-scale.product-agent-roster.v1",
        description: "Maps current authorized network reconnaissance.",
        runtimeBindingAgentIds: [
          "runtime:recon-z",
          "runtime:recon-a",
          "runtime:recon-a",
          "runtime:recon-unversioned",
        ],
        runtimeBindingVersions: [
          { id: "runtime:recon-z", version: "3" },
          { id: "runtime:recon-a", version: "2" },
          { id: "runtime:recon-a", version: "2" },
          { id: "runtime:version-only", version: "4" },
        ],
      },
    };
    expect(runtimeBindingSummaries(agent)).toEqual([
      { id: "runtime:recon-a", version: "2" },
      { id: "runtime:recon-unversioned", version: null },
      { id: "runtime:recon-z", version: "3" },
      { id: "runtime:version-only", version: "4" },
    ]);
    expect(productRosterSource(agent)).toBe("ti-scale.product-agent-roster.v1");
    expect(productRosterDescription(agent))
      .toBe("Maps current authorized network reconnaissance.");
  });

  test("keeps compatibility with early preview runtime binding receipts", () => {
    const agent = {
      version: "preview-v1",
      configuration: {
        runtimeBindings: [
          { id: "runtime:recon-z", version: "3" },
          { id: "runtime:recon-a", version: "2" },
        ],
      },
    };
    expect(runtimeBindingSummaries(agent)).toEqual([
      { id: "runtime:recon-a", version: "2" },
      { id: "runtime:recon-z", version: "3" },
    ]);
  });

  test("an explicit empty canonical projection does not revive stale preview bindings", () => {
    const agent = {
      version: "roster-v1",
      configuration: {
        runtimeBindingAgentIds: [],
        runtimeBindingVersions: [],
        runtimeBindings: [
          { id: "runtime:stale", version: "1" },
        ],
      },
    };
    expect(runtimeBindingSummaries(agent)).toEqual([]);
  });

  test("does not present an offline definition-only projection as an executable binding", () => {
    const agent = {
      version: "roster-v1",
      configuration: {
        runtimeBindingAgentIds: ["definition-only-recon"],
        runtimeBindingVersions: [{
          id: "definition-only-recon",
          version: "configured-runtime-v1",
        }],
        readiness: {
          status: "offline",
          boundAdapterCount: 1,
          enabledCapabilityCount: 0,
        },
      },
    };
    expect(runtimeBindingSummaries(agent)).toEqual([]);
  });

  test("does not invent a binding from a count-only or malformed projection", () => {
    const countOnly = {
      version: "roster-v1",
      configuration: {
        runtimeBindingCount: 2,
        runtimeBindings: [
          { id: "", version: "1" },
          { id: 42, version: "1" },
        ],
      },
    };
    expect(runtimeBindingSummaries(countOnly)).toEqual([]);
    expect(productRosterSource(countOnly)).toBe("roster-v1");
    expect(productRosterDescription(countOnly)).toBeNull();
  });

  test("separates canonical role coverage from unique internal runtime adapters", () => {
    const summary = productRosterReadinessSummary([
      {
        configuration: {
          runtimeBindings: [{ id: "runtime:shared-recon", version: "1" }],
        },
      },
      {
        configuration: {
          runtimeBindings: [{ id: "runtime:shared-recon", version: "1" }],
        },
      },
      {
        configuration: {
          runtimeBindings: [],
        },
      },
    ]);
    expect(summary).toEqual({
      canonicalRoleCount: 3,
      runtimeBoundRoleCount: 2,
      runtimeUnboundRoleCount: 1,
      executableRuntimeBindingCount: 1,
    });
  });
});
