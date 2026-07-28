import {
  existsSync,
} from "node:fs";
import { resolve } from "node:path";
import { playwrightChildEnvironment } from "./playwright-child-environment";

const applicationRoot = resolve(import.meta.dir, "..");
const cli = resolve(
  applicationRoot,
  "node_modules/@playwright/test/cli.js",
);
if (!existsSync(cli)) {
  throw new Error("The lock-installed Playwright CLI is unavailable");
}
const node = Bun.which("node");
if (!node) throw new Error("Node is required to run Playwright browser workers");
const arguments_ = Bun.argv.slice(2);

const child = Bun.spawn([
  node,
  cli,
  "test",
  ...arguments_,
], {
  cwd: applicationRoot,
  env: playwrightChildEnvironment({
    ...process.env,
    ...(arguments_.includes("--list")
      ? { TI_SCALE_E2E_DISCOVERY_ONLY: "1" }
      : {}),
  }),
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
});

const forward = (signal: "SIGINT" | "SIGTERM"): void => child.kill(signal);
process.once("SIGINT", () => forward("SIGINT"));
process.once("SIGTERM", () => forward("SIGTERM"));
try {
  process.exitCode = await child.exited;
} finally {
  const {
    E2E_RUN_ID,
    disposeManagedE2EInvocation,
  } = await import("../tests/e2e/support/environment");
  const { disposeManagedE2EStaticBuilds } = await import(
    "../server/static-release"
  );
  disposeManagedE2EStaticBuilds(E2E_RUN_ID);
  disposeManagedE2EInvocation();
}
