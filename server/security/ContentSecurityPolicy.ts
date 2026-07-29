/**
 * Playwright WebKit briefly appends `<style>body {}</style>` before taking a
 * screenshot so animation state is synchronized. Ti-Scale's browser matrix
 * retains screenshots on failure, including iPhone WebKit, so the strict CSP
 * permits only the SHA-256 digest of that inert stylesheet. This does not
 * authorize style attributes or any other inline stylesheet.
 */
export const WEBKIT_SCREENSHOT_SYNC_STYLE = "body {}" as const;
export const WEBKIT_SCREENSHOT_SYNC_STYLE_SOURCE =
  "'sha256-YjaKGiklmzC6wjXA513HAMmzus8VE61XCOT+SmwNZWA='" as const;

export function applicationStyleSourceDirective(): string {
  return `style-src 'self' ${WEBKIT_SCREENSHOT_SYNC_STYLE_SOURCE}`;
}

/**
 * The production browser and its event stream use relative `/api/v2/...`
 * paths. `blob:` is required only for locally decoded, validated GLB assets.
 * A split-development API origin belongs in Vite's proxy configuration, not
 * in the policy served by the application process.
 */
export function applicationConnectSourceDirective(): string {
  return "connect-src 'self' blob:";
}
