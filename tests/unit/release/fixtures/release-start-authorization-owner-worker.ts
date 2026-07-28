import { writeFileSync } from "node:fs";
import { acquireSharedReleaseLock } from "../../../../scripts/release/ReleaseExecutionBoundary";
import { authorizeNextReleaseServiceStart } from "../../../../scripts/release/ReleaseServiceStartAdmission";

const [journal, authorizationPath, lockPath, readyPath, now] = process.argv.slice(2);
if (!journal || !authorizationPath || !lockPath || !readyPath || !now) {
  throw new Error("release-start authorization owner fixture arguments are invalid");
}

const lock = acquireSharedReleaseLock(lockPath, "crash-before-systemctl-fixture");
const authorization = authorizeNextReleaseServiceStart(journal, {
  authorizationPath,
  now: new Date(now),
});
writeFileSync(readyPath, "authorization-live\n");

// The owning test deliberately SIGKILLs this process. Normal cleanup remains
// present only for an unexpected cooperative exit.
try { await Bun.sleep(60_000); }
finally {
  authorization.release();
  lock.release();
}
