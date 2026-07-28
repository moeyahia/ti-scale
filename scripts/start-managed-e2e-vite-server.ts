import {
  existsSync,
} from "node:fs";
import { resolve } from "node:path";
import { managedE2EChildEnvironment } from "./managed-e2e-child-environment";

const applicationRoot = resolve(import.meta.dir, "..");
const viteEntry = resolve(applicationRoot, "node_modules/vite/bin/vite.js");
if (!existsSync(viteEntry)) {
  throw new Error("The lock-installed Vite executable is unavailable");
}
const node = Bun.which("node");
if (!node) {
  throw new Error("Node is required to run the managed Vite development server");
}
const host = process.env.TI_SCALE_E2E_UI_HOST?.trim();
const port = process.env.TI_SCALE_E2E_UI_PORT?.trim();
if (!host || !port || !/^\d{1,5}$/u.test(port)) {
  throw new Error("Managed Vite requires explicit host and port values");
}

const child = Bun.spawn([
  node,
  viteEntry,
  "--host",
  host,
  "--port",
  port,
], {
  cwd: applicationRoot,
  env: managedE2EChildEnvironment({
    ...process.env,
    CHOKIDAR_USEPOLLING: "true",
    CHOKIDAR_INTERVAL: "1000",
  }),
  stdin: "ignore",
  stdout: "inherit",
  stderr: "inherit",
});

let forwardedSignal: "SIGINT" | "SIGTERM" | undefined;
const forward = (signal: "SIGINT" | "SIGTERM"): void => {
  forwardedSignal = signal;
  child.kill(signal);
};
process.once("SIGINT", () => forward("SIGINT"));
process.once("SIGTERM", () => forward("SIGTERM"));
const exitCode = await child.exited;
if (!forwardedSignal) {
  console.error(JSON.stringify({
    event: "managed-vite-unexpected-exit",
    exitCode,
    childPid: child.pid,
    timestamp: new Date().toISOString(),
  }));
}
process.exitCode = forwardedSignal ? exitCode : exitCode || 1;
