import { appendFileSync } from "node:fs";
import { createServer } from "node:http";
import { GracefulShutdownCoordinator } from "../../GracefulShutdownCoordinator";

const port = Number(process.env.TI_SCALE_SHUTDOWN_FIXTURE_PORT);
const finalizerPath = process.env.TI_SCALE_SHUTDOWN_FIXTURE_FINALIZER_PATH;
if (!Number.isSafeInteger(port) || port < 1_024 || port > 65_535 || !finalizerPath) {
  throw new Error("Shutdown deadline fixture configuration is invalid");
}

const server = createServer((_request, response) => {
  response.writeHead(200).end("ready");
});
await new Promise<void>((resolve, reject) => {
  server.once("error", reject);
  server.listen(port, "127.0.0.1", resolve);
});

let resolveHttpClosed!: () => void;
const httpClosed = new Promise<void>((resolve) => { resolveHttpClosed = resolve; });
const shutdown = new GracefulShutdownCoordinator({
  deadlineMs: 150,
  closeAdmission() {
    server.close(() => resolveHttpClosed());
    server.closeIdleConnections?.();
  },
  phases: [{
    name: "stuck",
    components: [{
      name: "promise-without-os-handle",
      stop: () => new Promise<void>(() => undefined),
    }],
  }, {
    name: "transport",
    components: [{ name: "http-server", stop: () => httpClosed }],
  }],
  forceClose() { server.closeAllConnections?.(); },
  finalizers: [{
    name: "deadline-finalizer",
    finalize() { appendFileSync(finalizerPath, "finalized\n", { encoding: "utf8" }); },
  }],
});

let handled = false;
const onSignal = (): void => {
  if (handled) return;
  handled = true;
  void shutdown.shutdown("SIGTERM").then((report) => {
    process.stdout.write(
      `DEADLINE_REPORT ${JSON.stringify({
        outcome: report.outcome,
        pending: report.pendingComponentNames,
        failed: report.failedComponentNames,
      })}\n`,
      () => process.exit(report.outcome === "timed_out" ? 1 : 2),
    );
  });
};
process.on("SIGTERM", onSignal);
process.stdout.write("DEADLINE_READY\n");
