import { describe, expect, test } from "bun:test";
import { graphZoomPercent } from "../../../src/features/brain/graphUtils";

describe("memory graph viewport status", () => {
  test("reports the bounded zoom percentage used by the canvas controls", () => {
    expect(graphZoomPercent(1)).toBe(100);
    expect(graphZoomPercent(1.2)).toBe(120);
    expect(graphZoomPercent(1 / 1.2)).toBe(83);
    expect(graphZoomPercent(0.01)).toBe(45);
    expect(graphZoomPercent(8)).toBe(280);
  });

  test("falls back safely when a non-finite camera value reaches the status projection", () => {
    expect(graphZoomPercent(Number.NaN)).toBe(100);
    expect(graphZoomPercent(Number.POSITIVE_INFINITY)).toBe(100);
  });
});
