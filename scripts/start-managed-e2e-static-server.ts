import {
  existsSync,
  rmSync,
} from "node:fs";
import { resolve } from "node:path";
import { resolveManagedE2EStaticBuild } from "../server/static-release/ManagedE2EStaticBuild";
import { managedE2EChildEnvironment } from "./managed-e2e-child-environment";

const applicationRoot = new URL("..", import.meta.url).pathname;
const dist = resolveManagedE2EStaticBuild(process.env);
if (!dist) throw new Error("The managed E2E static build path is not configured");
if (existsSync(dist)) {
  throw new Error(
    "The managed E2E static build path already exists; use a fresh E2E run ID",
  );
}

const viteEntry = resolve(applicationRoot, "node_modules/vite/bin/vite.js");
if (!existsSync(viteEntry)) {
  throw new Error("The lock-installed Vite executable is unavailable");
}
const childEnvironment = managedE2EChildEnvironment(process.env);

let child: ReturnType<typeof Bun.spawn> | undefined;
let ownsBuildRoot = false;
let forwardedSignal: "SIGINT" | "SIGTERM" | undefined;
const forwardSignal = (signal: "SIGINT" | "SIGTERM"): void => {
  if (forwardedSignal) return;
  forwardedSignal = signal;
  child?.kill(signal);
};
const onInterrupt = (): void => forwardSignal("SIGINT");
const onTerminate = (): void => forwardSignal("SIGTERM");
process.on("SIGINT", onInterrupt);
process.on("SIGTERM", onTerminate);

try {
  ownsBuildRoot = true;
  child = Bun.spawn([
    process.execPath,
    viteEntry,
    "build",
    "--outDir",
    dist,
    "--emptyOutDir",
  ], {
    cwd: applicationRoot,
    env: childEnvironment,
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });
  const buildExitCode = await child.exited;
  if (buildExitCode !== 0) {
    throw new Error(`The managed E2E static build failed with exit code ${buildExitCode}`);
  }
  resolveManagedE2EStaticBuild(process.env, { requireBuiltArtifact: true });
  if (forwardedSignal) {
    process.exitCode = 128 + (forwardedSignal === "SIGINT" ? 2 : 15);
  } else {
    child = Bun.spawn([process.execPath, "run", "server/index.ts"], {
      cwd: applicationRoot,
      env: childEnvironment,
      stdin: "ignore",
      stdout: "inherit",
      stderr: "inherit",
    });
    process.exitCode = await child.exited;
  }
} finally {
  process.off("SIGINT", onInterrupt);
  process.off("SIGTERM", onTerminate);
  if (ownsBuildRoot) rmSync(dist, { recursive: true, force: true });
}
