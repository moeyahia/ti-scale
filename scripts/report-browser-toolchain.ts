import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const packageDocument = JSON.parse(
  readFileSync(resolve(root, "node_modules/@playwright/test/package.json"), "utf8"),
) as { readonly version?: string };
const browserManifest = readFileSync(
  resolve(root, "node_modules/playwright-core/browsers.json"),
);
const parsedBrowserManifest = JSON.parse(browserManifest.toString("utf8")) as {
  readonly browsers?: readonly {
    readonly name?: string;
    readonly revision?: string;
    readonly browserVersion?: string;
  }[];
};
const operatingSystem = readFileSync("/etc/os-release", "utf8")
  .split("\n")
  .filter((line) => /^(?:ID|VERSION_ID)=/u.test(line))
  .join(" ");

console.log(JSON.stringify({
  playwrightVersion: packageDocument.version,
  browserManifestSha256: createHash("sha256")
    .update(browserManifest)
    .digest("hex"),
  browsers: parsedBrowserManifest.browsers?.map((browser) => ({
    name: browser.name,
    revision: browser.revision,
    browserVersion: browser.browserVersion,
  })),
  nodeVersion: process.version,
  bunVersion: Bun.version,
  operatingSystem,
}, null, 2));
