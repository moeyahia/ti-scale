import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import {
  applicationConnectSourceDirective,
  applicationStyleSourceDirective,
  WEBKIT_SCREENSHOT_SYNC_STYLE,
  WEBKIT_SCREENSHOT_SYNC_STYLE_SOURCE,
} from "../ContentSecurityPolicy";

describe("application style content-security policy", () => {
  test("allows only the exact inert WebKit screenshot synchronization stylesheet", () => {
    const digest = createHash("sha256")
      .update(WEBKIT_SCREENSHOT_SYNC_STYLE, "utf8")
      .digest("base64");

    expect(WEBKIT_SCREENSHOT_SYNC_STYLE).toBe("body {}");
    expect(String(WEBKIT_SCREENSHOT_SYNC_STYLE_SOURCE)).toBe(`'sha256-${digest}'`);
    expect(applicationStyleSourceDirective()).toBe(
      `style-src 'self' 'sha256-${digest}'`,
    );
  });

  test("does not authorize arbitrary inline styles", () => {
    const directive = applicationStyleSourceDirective();

    expect(directive).not.toContain("'unsafe-inline'");
    expect(directive).not.toContain("'unsafe-eval'");
    expect(directive.match(/'sha256-/gu)).toHaveLength(1);
  });
});

describe("application connection content-security policy", () => {
  test("keeps production API and event requests same-origin", () => {
    expect(applicationConnectSourceDirective()).toBe("connect-src 'self' blob:");
  });

  test("does not authorize the split-development API server", () => {
    const directive = applicationConnectSourceDirective();

    expect(directive).not.toContain("43141");
    expect(directive).not.toContain("localhost");
    expect(directive).not.toContain("127.0.0.1");
    expect(directive).not.toContain("http:");
    expect(directive).not.toContain("https:");
  });
});
