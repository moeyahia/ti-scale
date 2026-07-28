import { afterEach, describe, expect, test } from "bun:test";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OpenRouterConnectionError,
  OpenRouterConnectionStore,
} from "../index";

const KEY = "sk-or-v1-test-private-value-that-must-never-be-echoed";
const REPLACEMENT_KEY = "sk-or-v1-replacement-private-value-never-retained";
const roots: string[] = [];

function store(): OpenRouterConnectionStore {
  const root = mkdtempSync(join(tmpdir(), "ti-scale-openrouter-store-"));
  roots.push(root);
  return new OpenRouterConnectionStore({
    root: join(root, "provider-config"),
    clock: () => new Date("2026-07-24T10:00:00.000Z"),
  });
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("OpenRouter connection store", () => {
  test("atomically stores private service-owned files without echoing or copying the secret", () => {
    const repository = store();
    const saved = repository.put({
      enabled: true,
      model: "openai/gpt-5.2",
      credential: { action: "replace", value: KEY },
      expectedVersion: 0,
    }, "operator:test", "openrouter-save-0001");

    expect(saved).toMatchObject({
      replayed: false,
      configuration: {
        enabled: true,
        model: "openai/gpt-5.2",
        version: 1,
        updatedBy: "operator:test",
      },
    });
    expect(JSON.stringify(saved)).not.toContain(KEY);
    expect(lstatSync(repository.root).mode & 0o777).toBe(0o700);
    expect(lstatSync(repository.configurationPath).mode & 0o777).toBe(0o600);
    expect(lstatSync(repository.credentialPath).mode & 0o777).toBe(0o600);
    expect(readFileSync(repository.credentialPath, "utf8").trim()).toBe(KEY);
    expect(readFileSync(repository.configurationPath, "utf8")).not.toContain(KEY);
    expect(readdirSync(repository.root).sort()).toEqual([
      "openrouter.credential",
      "openrouter.json",
    ]);

    repository.put({
      enabled: true,
      model: "anthropic/claude-sonnet-4.5",
      credential: { action: "replace", value: REPLACEMENT_KEY },
      expectedVersion: 1,
    }, "operator:test", "openrouter-save-0005");
    expect(readFileSync(repository.credentialPath, "utf8").trim())
      .toBe(REPLACEMENT_KEY);
    expect(readFileSync(repository.credentialPath, "utf8")).not.toContain(KEY);
    expect(readdirSync(repository.root).sort()).toEqual([
      "openrouter.credential",
      "openrouter.json",
    ]);
    expect(readdirSync(repository.root).some((name) =>
      /(?:backup|previous|\\.bak|\\.old|~$)/iu.test(name))).toBe(false);
  });

  test("replays an identical idempotent save and rejects key reuse or stale versions", () => {
    const repository = store();
    const request = {
      enabled: true,
      model: "openai/gpt-5.2",
      credential: { action: "replace", value: KEY } as const,
      expectedVersion: 0,
    };
    expect(repository.put(request, "operator:test", "openrouter-save-0002").replayed)
      .toBe(false);
    expect(repository.put(request, "operator:test", "openrouter-save-0002")).toMatchObject({
      replayed: true,
      configuration: { version: 1 },
    });

    expect(() => repository.put({
      ...request,
      model: "anthropic/claude-sonnet-4.5",
    }, "operator:test", "openrouter-save-0002")).toThrow(
      OpenRouterConnectionError,
    );
    expect(() => repository.put({
      enabled: true,
      model: "openai/gpt-5.2",
      credential: { action: "keep" },
      expectedVersion: 0,
    }, "operator:test", "openrouter-save-0003")).toThrow(
      "changed from expected version 0 to 1",
    );
  });

  test("requires an explicit credential removal when disabled", () => {
    const repository = store();
    repository.put({
      enabled: true,
      model: "openai/gpt-5.2",
      credential: { action: "replace", value: KEY },
      expectedVersion: 0,
    }, "operator:test", "openrouter-save-0004");

    const disabled = repository.put({
      enabled: false,
      model: "openai/gpt-5.2",
      credential: { action: "remove" },
      expectedVersion: 1,
    }, "operator:test", "openrouter-disable-0001");
    expect(disabled).toMatchObject({
      configuration: {
        enabled: false,
        credentialSha256: null,
        version: 2,
      },
    });
    expect(readdirSync(repository.root).sort()).toEqual(["openrouter.json"]);
  });
});
