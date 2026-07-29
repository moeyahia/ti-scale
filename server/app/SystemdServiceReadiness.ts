import { spawnSync } from "node:child_process";

const CONTROL = /[\u0000-\u001F\u007F]/u;
const MAXIMUM_STATUS_LENGTH = 240;
const SYSTEMD_NOTIFY = "/usr/bin/systemd-notify";

export interface SystemdReadinessReceipt {
  readonly notified: boolean;
  readonly status: string;
}

/**
 * Tell systemd that a Type=notify service has completed its application-level
 * startup checks.
 *
 * The call is deliberately a no-op outside systemd so the same compiled
 * entrypoint remains testable in an isolated process. Under systemd it fails
 * closed: a missing or rejected notification leaves the unit in "activating"
 * until TimeoutStartSec terminates it.
 *
 * NotifyAccess=all is required by the checked-in units because
 * /usr/bin/systemd-notify is a short-lived child. Only NOTIFY_SOCKET is passed
 * to that child; no provider, target process, or general service environment is
 * exposed through this lifecycle boundary.
 */
export function notifySystemdServiceReady(
  statusValue: string,
): SystemdReadinessReceipt {
  const status = statusValue.trim();
  if (
    status.length < 1
    || status.length > MAXIMUM_STATUS_LENGTH
    || CONTROL.test(status)
  ) {
    throw new Error("Systemd readiness status is invalid");
  }
  const notifySocket = process.env.NOTIFY_SOCKET?.trim();
  if (!notifySocket) {
    return Object.freeze({ notified: false, status });
  }
  const result = spawnSync(
    SYSTEMD_NOTIFY,
    ["--ready", `--status=${status}`],
    {
      encoding: "utf8",
      env: Object.freeze({ NOTIFY_SOCKET: notifySocket }),
      shell: false,
      timeout: 5_000,
      windowsHide: true,
    },
  );
  if (
    result.error
    || result.signal !== null
    || result.status !== 0
  ) {
    const detail = (result.stderr || result.error?.message || "notification rejected")
      .replace(/[\u0000-\u001F\u007F]/gu, " ")
      .replace(/\s+/gu, " ")
      .trim()
      .slice(0, 300);
    throw new Error(
      `Systemd readiness notification failed: ${detail || "notification rejected"}`,
    );
  }
  return Object.freeze({ notified: true, status });
}
