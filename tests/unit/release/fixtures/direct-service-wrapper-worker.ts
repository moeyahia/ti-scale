import { resolve } from "node:path";
import { runReleaseServiceWrapper } from "../../../../scripts/release/service-wrapper";

const applicationPath = process.argv[2];
if (!applicationPath) throw new Error("Direct service-wrapper fixture requires an application root");

await runReleaseServiceWrapper({
  invocationId: "a".repeat(32),
  barrierExists: () => false,
  applicationPath: resolve(applicationPath),
  bunPath: process.execPath,
});
