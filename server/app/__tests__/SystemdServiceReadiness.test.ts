import { afterEach, describe, expect, test } from "bun:test";
import {
  notifySystemdServiceReady,
} from "../SystemdServiceReadiness";

const originalNotifySocket = process.env.NOTIFY_SOCKET;

afterEach(() => {
  if (originalNotifySocket === undefined) {
    delete process.env.NOTIFY_SOCKET;
  } else {
    process.env.NOTIFY_SOCKET = originalNotifySocket;
  }
});

describe("systemd service readiness", () => {
  test("is an explicit no-op outside a systemd service", () => {
    delete process.env.NOTIFY_SOCKET;
    expect(
      notifySystemdServiceReady("Reviewed transport is ready"),
    ).toEqual({
      notified: false,
      status: "Reviewed transport is ready",
    });
  });

  test("rejects unbounded or control-bearing status text", () => {
    delete process.env.NOTIFY_SOCKET;
    expect(() => notifySystemdServiceReady("ready\nforged")).toThrow(
      "Systemd readiness status is invalid",
    );
    expect(() => notifySystemdServiceReady("x".repeat(241))).toThrow(
      "Systemd readiness status is invalid",
    );
  });

  test("fails closed when systemd rejects the readiness notification", () => {
    process.env.NOTIFY_SOCKET =
      "/tmp/ti-scale-systemd-notify-socket-does-not-exist";
    expect(() =>
      notifySystemdServiceReady("Reviewed transport is ready")
    ).toThrow("Systemd readiness notification failed");
  });
});
