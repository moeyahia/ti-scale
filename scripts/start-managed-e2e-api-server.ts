import { resolve } from "node:path";
import { managedE2EChildEnvironment } from "./managed-e2e-child-environment";

const applicationRoot = resolve(import.meta.dir, "..");
const child = Bun.spawn([process.execPath, "run", "server/index.ts"], {
  cwd: applicationRoot,
  env: managedE2EChildEnvironment(process.env),
  stdin: "ignore",
  stdout: "inherit",
  stderr: "inherit",
});

const forward = (signal: "SIGINT" | "SIGTERM"): void => child.kill(signal);
process.once("SIGINT", () => forward("SIGINT"));
process.once("SIGTERM", () => forward("SIGTERM"));
process.exitCode = await child.exited;
