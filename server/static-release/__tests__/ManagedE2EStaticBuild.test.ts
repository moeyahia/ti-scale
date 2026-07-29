import {
  afterEach,
  describe,
  expect,
  test,
} from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  disposeManagedE2EStaticBuilds,
  resolveManagedE2EStaticBuild,
} from "../ManagedE2EStaticBuild";

const roots: string[] = [];

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-managed-e2e-static-"));
  roots.push(root);
  const baseRoot = join(root, "ti-scale-e2e-data");
  const runId = "managed-static-contract";
  const buildId = `e2e-${runId}-12345`;
  const dist = join(baseRoot, `static-build-${buildId}`);
  mkdirSync(baseRoot);
  const environment = {
    TI_SCALE_DIST_ROOT: dist,
    TI_SCALE_E2E_RUN_ID: runId,
    TI_SCALE_E2E_STATIC_BUILD_ID: buildId,
    TI_SCALE_PREVIEW: "true",
    TI_SCALE_SERVE_STATIC: "true",
  };
  return { baseRoot, buildId, dist, environment };
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("managed E2E static build boundary", () => {
  test("admits only this run's direct disposable build before and after Vite output", () => {
    const input = fixture();
    expect(resolveManagedE2EStaticBuild(input.environment, {
      baseRoot: input.baseRoot,
    })).toBe(input.dist);

    mkdirSync(input.dist);
    writeFileSync(join(input.dist, "index.html"), "<!doctype html><main>Ti-Scale</main>");
    expect(resolveManagedE2EStaticBuild(input.environment, {
      baseRoot: input.baseRoot,
      requireBuiltArtifact: true,
    })).toBe(input.dist);
    expect(disposeManagedE2EStaticBuilds(
      input.environment.TI_SCALE_E2E_RUN_ID,
      input.baseRoot,
    )).toEqual([input.dist]);
    expect(disposeManagedE2EStaticBuilds(
      input.environment.TI_SCALE_E2E_RUN_ID,
      input.baseRoot,
    )).toEqual([]);
  });

  test("rejects release stores, other paths, other runs, and non-preview serving", () => {
    const input = fixture();
    expect(() => resolveManagedE2EStaticBuild({
      ...input.environment,
      TI_SCALE_STATIC_RELEASE_ROOT: join(input.baseRoot, "static-releases"),
    }, { baseRoot: input.baseRoot })).toThrow("cannot be combined");
    expect(() => resolveManagedE2EStaticBuild({
      ...input.environment,
      TI_SCALE_DIST_ROOT: join(input.baseRoot, "another-build"),
    }, { baseRoot: input.baseRoot })).toThrow("must exactly match");
    expect(() => resolveManagedE2EStaticBuild({
      ...input.environment,
      TI_SCALE_E2E_STATIC_BUILD_ID: "e2e-another-run-12345",
    }, { baseRoot: input.baseRoot })).toThrow("not bound to this run");
    expect(() => resolveManagedE2EStaticBuild({
      ...input.environment,
      TI_SCALE_PREVIEW: "false",
    }, { baseRoot: input.baseRoot })).toThrow("requires preview static serving");
  });
});
