import { appendFileSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import {
  BubblewrapToolProbeEnvironment,
  LocalToolCapabilityManifest,
  parseBubblewrapProbeSandboxDescriptor,
} from "../../../local-tools";
import {
  ToolBindingReadinessRunner,
  ToolBindingRegistry,
  ToolExecutionPreflightService,
} from "../../../system-capabilities";
import { GracefulShutdownCoordinator } from "../../GracefulShutdownCoordinator";

const port = Number(process.env.TI_SCALE_SHUTDOWN_FIXTURE_PORT);
const executablePath = process.env.TI_SCALE_SHUTDOWN_FIXTURE_EXECUTABLE;
const executableSha256 = process.env.TI_SCALE_SHUTDOWN_FIXTURE_EXECUTABLE_SHA256;
const finalizerPath = process.env.TI_SCALE_SHUTDOWN_FIXTURE_FINALIZER_PATH;
if (!Number.isSafeInteger(port) || port < 1_024 || port > 65_535
  || !executablePath || !/^[a-f0-9]{64}$/u.test(executableSha256 ?? "")
  || !finalizerPath) {
  throw new Error("Shutdown process fixture configuration is invalid");
}

const toolTemplate = new URL(
  "../../../../deployment/runtime-config/local-tool-capabilities.v1.json",
  import.meta.url,
);
const sandboxTemplate = new URL(
  "../../../../deployment/runtime-config/bubblewrap-probe-sandbox.v1.json",
  import.meta.url,
);
const document = JSON.parse(readFileSync(toolTemplate, "utf8")) as {
  schemaVersion: string;
  manifestVersion: string;
  specialist: Readonly<{ id: string; label: string }>;
  tools: Array<Record<string, unknown>>;
};
const base = document.tools.find(({ toolId }) => toolId === "kali:curl-http-metadata");
if (!base) throw new Error("Shutdown fixture tool template is missing");
const baseProbe = base.probe as Record<string, unknown>;
const baseExecutable = base.executable as Record<string, unknown>;
document.manifestVersion = "shutdown-active-refresh-fixture.v1";
document.tools = [{
  ...base,
  executable: {
    ...baseExecutable,
    path: executablePath,
    expectedSha256: executableSha256,
  },
  probe: {
    ...baseProbe,
    timeoutMs: 2_000,
  },
}];

const manifest = new LocalToolCapabilityManifest(document);
const registry = new ToolBindingRegistry(
  manifest.toToolBindingRegistryDocument(),
  manifest.toRuntimeSourceManifests(),
);
const sandbox = parseBubblewrapProbeSandboxDescriptor(
  JSON.parse(readFileSync(sandboxTemplate, "utf8")),
);
const runner = new ToolBindingReadinessRunner(
  registry,
  new ToolExecutionPreflightService({
    environment: new BubblewrapToolProbeEnvironment(sandbox),
  }),
);

const server = createServer((_request, response) => {
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end('{"status":"ready"}');
});
await new Promise<void>((resolve, reject) => {
  server.once("error", reject);
  server.listen(port, "127.0.0.1", resolve);
});

const activeRefresh = runner.startMonitoring();
void activeRefresh.catch(() => undefined);
// Give the real Bubblewrap readiness stack enough time to enter its bounded
// child probe before advertising the signal point to the parent process.
await new Promise((resolve) => setTimeout(resolve, 150));
process.stdout.write("ACTIVE_REFRESH\n");

let resolveHttpClosed!: () => void;
let rejectHttpClosed!: (error: Error) => void;
const httpClosed = new Promise<void>((resolve, reject) => {
  resolveHttpClosed = resolve;
  rejectHttpClosed = reject;
});
let admissionClosed = false;
const shutdown = new GracefulShutdownCoordinator({
  deadlineMs: 4_000,
  closeAdmission() {
    if (admissionClosed) return;
    admissionClosed = true;
    server.close((error) => error ? rejectHttpClosed(error) : resolveHttpClosed());
    server.closeIdleConnections?.();
  },
  forceClose() { server.closeAllConnections?.(); },
  phases: [
    {
      name: "readiness",
      components: [{
        name: "real-tool-binding-readiness",
        stop: () => runner.stop().then(() => undefined),
      }],
    },
    {
      name: "transport",
      components: [{ name: "http-server", stop: () => httpClosed }],
    },
  ],
  finalizers: [{
    name: "fixture-finalizer",
    finalize() { appendFileSync(finalizerPath, "finalized\n", { encoding: "utf8" }); },
  }],
});

let handled = false;
const onSignal = (signal: "SIGINT" | "SIGTERM"): void => {
  if (handled) return;
  handled = true;
  void shutdown.shutdown(signal).then((report) => {
    process.stdout.write(
      `SHUTDOWN_REPORT ${JSON.stringify({
        outcome: report.outcome,
        pending: report.pendingComponentNames,
        failed: report.failedComponentNames,
      })}\n`,
      () => process.exit(report.outcome === "completed" ? 0 : 1),
    );
  });
};
process.on("SIGTERM", () => onSignal("SIGTERM"));
process.on("SIGINT", () => onSignal("SIGINT"));

// Keep a real referenced handle in addition to the HTTP listener so an
// accidental early server close cannot make the fixture look successful.
const keepAlive = setInterval(() => undefined, 1_000);
process.once("exit", () => clearInterval(keepAlive));
