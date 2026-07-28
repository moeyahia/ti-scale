import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { resolveOperationalHazardObservationKey } from "../OperationalHazardObservationKey";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function directory(): string {
  const value = mkdtempSync(join(tmpdir(), "ti-scale-hazard-key-"));
  directories.push(value);
  return value;
}

describe("OperationalHazardObservationKey", () => {
  test("creates one stable private companion key and reuses it after restart", () => {
    const root = directory();
    const databasePath = join(root, "ti-scale.sqlite");
    const first = resolveOperationalHazardObservationKey({ databasePath, environment: {} });
    const second = resolveOperationalHazardObservationKey({ databasePath, environment: {} });
    const keyPath = `${databasePath}.operational-hazard-hmac`;
    expect(first.equals(second)).toBe(true);
    expect(first.byteLength).toBeGreaterThanOrEqual(32);
    expect(statSync(keyPath).mode & 0o777).toBe(0o600);
    expect(readFileSync(keyPath, "utf8").trim()).not.toContain(" ");
  });

  test("rejects world-readable files, ambiguous configuration, and multiline inline secrets", () => {
    const root = directory();
    const keyPath = join(root, "hazard.key");
    writeFileSync(keyPath, `${"k".repeat(48)}\n`, "utf8");
    chmodSync(keyPath, 0o644);
    expect(() => resolveOperationalHazardObservationKey({
      databasePath: join(root, "state.sqlite"),
      environment: { TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE: keyPath },
    })).toThrow("must not be accessible");
    expect(() => resolveOperationalHazardObservationKey({
      databasePath: join(root, "state.sqlite"),
      environment: {
        TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY: "a".repeat(48),
        TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY_FILE: keyPath,
      },
    })).toThrow("not both");
    expect(() => resolveOperationalHazardObservationKey({
      databasePath: join(root, "state.sqlite"),
      environment: { TI_SCALE_OPERATIONAL_HAZARD_HMAC_KEY: `${"a".repeat(32)}\nforged` },
    })).toThrow("bounded line");
  });
});
