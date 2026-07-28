import { writeFileSync } from "node:fs";
import {
  runBoundedReleaseCommand,
  runBoundedReleaseCommandSync,
} from "../../../../scripts/release/BoundedReleaseCommand";
import { acquireSharedReleaseLock } from "../../../../scripts/release/ReleaseExecutionBoundary";

const [mode, lockPath, childReadyPath, childCompletedPath, parentReadyPath] = process.argv.slice(2);
if (
  (mode !== "async" && mode !== "sync") ||
  !lockPath || !childReadyPath || !childCompletedPath || !parentReadyPath
) throw new Error("bounded release lock-holder fixture arguments are invalid");

const lock = acquireSharedReleaseLock(lockPath, `orphan-containment-${mode}`);
writeFileSync(parentReadyPath, "lock-held\n");
const command = [
  "/usr/bin/bash",
  "-c",
  mode === "sync"
    // Keep the synchronous target live while its child runs. Otherwise the
    // bounded sync helper correctly cleans up a residual background process
    // before this fixture's parent can be killed, which does not exercise the
    // parent-SIGKILL inheritance boundary.
    ? "printf 'ready\\n' > \"$1\"; (sleep 2; printf 'completed\\n' > \"$2\") & wait"
    : "printf 'ready\\n' > \"$1\"; (sleep 2; printf 'completed\\n' > \"$2\") </dev/null >/dev/null 2>&1 & exit 0",
  "bounded-release-orphan-fixture",
  childReadyPath,
  childCompletedPath,
] as const;

try {
  if (mode === "async") {
    await runBoundedReleaseCommand(command, { timeoutMs: 10_000 });
  } else {
    runBoundedReleaseCommandSync(command, { timeoutMs: 10_000 });
  }
  // Keep the release parent alive after the immediate target exits. The test
  // kills this process and proves the background descendant's inherited lock
  // FD—not this parent—continues excluding reconciliation.
  await Bun.sleep(10_000);
} finally {
  lock.release();
}
