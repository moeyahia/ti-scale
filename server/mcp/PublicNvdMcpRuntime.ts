import {
  PUBLIC_NVD_SERVER_NAME,
  PUBLIC_NVD_SERVER_VERSION,
  PUBLIC_NVD_TOOL_NAME,
} from "../mcp-public-nvd";
import { BoundedStreamableHttpTransportFactory } from "./BoundedStreamableHttpTransportFactory";
import {
  createPublicNvdMcpConnectionConfig,
  PUBLIC_NVD_MCP_CONNECTION_ID,
  PUBLIC_NVD_MCP_CREDENTIAL_ID,
  PUBLIC_NVD_INPUT_SCHEMA_SHA256,
  PUBLIC_NVD_OUTPUT_SCHEMA_SHA256,
} from "./PublicNvdMcpConfiguration";
import {
  PublicNvdMcpToolClient,
  PublicNvdToolBoundaryError,
} from "./PublicNvdMcpToolClient";
import {
  SystemdCredentialStore,
  systemdCredentialStoreFromEnvironment,
} from "./SystemdCredentialStore";
import type { McpCapabilityAttestation } from "./types";

export type PublicNvdMcpRuntimeStatus =
  | "unavailable"
  | "probing"
  | "degraded"
  | "ready"
  | "stopped";

export interface PublicNvdMcpRuntimeSnapshot {
  readonly status: PublicNvdMcpRuntimeStatus;
  readonly credentialMounted: boolean;
  /** True only while the exact live server identity, inventory, and schemas are fresh. */
  readonly attested: boolean;
  readonly toolNames: readonly string[];
  readonly lastCheckedAt?: string;
  readonly attestedAt?: string;
  readonly expiresAt?: string;
  readonly manifestSha256?: string;
  readonly reason: string;
}

export interface PublicNvdMcpRuntimeOptions {
  readonly client: Pick<PublicNvdMcpToolClient, "refreshAttestation">;
  readonly credentialAvailable: () => boolean;
  readonly now?: () => Date;
  readonly refreshIntervalMs?: number;
}

function isExactReviewedAttestation(attestation: McpCapabilityAttestation): boolean {
  const tool = attestation.tools[0];
  return attestation.connectionId === PUBLIC_NVD_MCP_CONNECTION_ID
    && attestation.server.name === PUBLIC_NVD_SERVER_NAME
    && attestation.server.version === PUBLIC_NVD_SERVER_VERSION
    && attestation.executionAuthorization === "none"
    && attestation.tools.length === 1
    && tool?.name === PUBLIC_NVD_TOOL_NAME
    && tool.inputSchemaSha256 === PUBLIC_NVD_INPUT_SCHEMA_SHA256
    && tool.outputSchemaSha256 === PUBLIC_NVD_OUTPUT_SCHEMA_SHA256
    && tool.annotations.readOnlyHint === true
    && tool.annotations.destructiveHint === false
    && tool.annotations.idempotentHint === true
    && tool.annotations.openWorldHint === true;
}

function safeFailureReason(error: unknown): string {
  if (error instanceof PublicNvdToolBoundaryError) {
    return error.code === "ATTESTATION_REJECTED"
      ? "The public NVD sidecar did not pass its exact live identity, inventory, and schema attestation."
      : "The public NVD sidecar could not complete a bounded live capability check.";
  }
  return "The public NVD sidecar could not complete a bounded live capability check.";
}

/**
 * Owns only dependency discovery and exact capability attestation. It exposes
 * no invocation method and cannot authorize a mission action. A host may share
 * its exact client only with a separately reviewed mission-scoped public-read
 * adapter. That adapter still grants no target, specialist, run, Guided, or
 * Autonomous execution authority.
 */
export class PublicNvdMcpRuntime {
  private readonly client: PublicNvdMcpRuntimeOptions["client"];
  private readonly credentialAvailable: () => boolean;
  private readonly now: () => Date;
  private readonly refreshIntervalMs: number;
  private state: PublicNvdMcpRuntimeSnapshot;
  private timer: ReturnType<typeof setInterval> | undefined;
  private inFlight: Promise<PublicNvdMcpRuntimeSnapshot> | undefined;
  private stopped = false;

  constructor(options: PublicNvdMcpRuntimeOptions) {
    this.client = options.client;
    this.credentialAvailable = options.credentialAvailable;
    this.now = options.now ?? (() => new Date());
    this.refreshIntervalMs = options.refreshIntervalMs ?? 45_000;
    if (!Number.isSafeInteger(this.refreshIntervalMs)
      || this.refreshIntervalMs < 1_000
      || this.refreshIntervalMs > 300_000) {
      throw new RangeError("Public NVD refresh interval must be between 1 and 300 seconds");
    }
    this.state = Object.freeze({
      status: "unavailable",
      credentialMounted: false,
      attested: false,
      toolNames: Object.freeze([]),
      reason: "The public NVD systemd credential has not been verified.",
    });
  }

  snapshot(): PublicNvdMcpRuntimeSnapshot {
    const state = this.state;
    if (state.status !== "ready" || !state.expiresAt) return state;
    if (Date.parse(state.expiresAt) > this.now().getTime()) return state;
    return Object.freeze({
      status: "degraded",
      credentialMounted: state.credentialMounted,
      attested: false,
      toolNames: Object.freeze([]),
      ...(state.lastCheckedAt ? { lastCheckedAt: state.lastCheckedAt } : {}),
      ...(state.attestedAt ? { attestedAt: state.attestedAt } : {}),
      expiresAt: state.expiresAt,
      reason: "The public NVD live capability attestation expired; no capability is advertised until it is refreshed.",
    });
  }

  refreshNow(): Promise<PublicNvdMcpRuntimeSnapshot> {
    if (this.inFlight) return this.inFlight;
    const pending = this.performRefresh().finally(() => {
      if (this.inFlight === pending) this.inFlight = undefined;
    });
    this.inFlight = pending;
    return pending;
  }

  private async performRefresh(): Promise<PublicNvdMcpRuntimeSnapshot> {
    if (this.stopped) {
      this.state = Object.freeze({
        status: "stopped",
        credentialMounted: false,
        attested: false,
        toolNames: Object.freeze([]),
        reason: "The public NVD capability monitor is stopped.",
      });
      return this.state;
    }

    let credentialMounted = false;
    try {
      credentialMounted = this.credentialAvailable();
    } catch {
      credentialMounted = false;
    }
    const checkedAt = this.now().toISOString();
    if (!credentialMounted) {
      this.state = Object.freeze({
        status: "unavailable",
        credentialMounted: false,
        attested: false,
        toolNames: Object.freeze([]),
        lastCheckedAt: checkedAt,
        reason: `The ${PUBLIC_NVD_MCP_CREDENTIAL_ID} systemd credential is not mounted; no network attestation was attempted.`,
      });
      return this.state;
    }

    this.state = Object.freeze({
      status: "probing",
      credentialMounted: true,
      attested: false,
      toolNames: Object.freeze([]),
      lastCheckedAt: checkedAt,
      reason: "The public NVD sidecar is completing an exact live identity, inventory, and schema check.",
    });

    try {
      const attestation = await this.client.refreshAttestation();
      const completedAt = this.now().toISOString();
      if (!isExactReviewedAttestation(attestation)
        || Date.parse(attestation.expiresAt) <= this.now().getTime()) {
        this.state = Object.freeze({
          status: "degraded",
          credentialMounted: true,
          attested: false,
          toolNames: Object.freeze([]),
          lastCheckedAt: completedAt,
          reason: "The public NVD sidecar returned a capability attestation outside the exact reviewed contract.",
        });
        return this.state;
      }
      this.state = Object.freeze({
        status: "ready",
        credentialMounted: true,
        attested: true,
        toolNames: Object.freeze([PUBLIC_NVD_TOOL_NAME]),
        lastCheckedAt: completedAt,
        attestedAt: attestation.attestedAt,
        expiresAt: attestation.expiresAt,
        manifestSha256: attestation.manifestSha256,
        reason: "The read-only public NVD sidecar passed its exact live identity, inventory, and schema attestation. Tool execution remains disabled.",
      });
      return this.state;
    } catch (error) {
      this.state = Object.freeze({
        status: "degraded",
        credentialMounted: true,
        attested: false,
        toolNames: Object.freeze([]),
        lastCheckedAt: this.now().toISOString(),
        reason: safeFailureReason(error),
      });
      return this.state;
    }
  }

  start(): void {
    if (this.stopped || this.timer) return;
    void this.refreshNow();
    this.timer = setInterval(() => void this.refreshNow(), this.refreshIntervalMs);
    this.timer.unref?.();
  }

  beginStop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.stopped = true;
  }

  async stop(): Promise<void> {
    this.beginStop();
    await this.inFlight;
    this.state = Object.freeze({
      status: "stopped",
      credentialMounted: false,
      attested: false,
      toolNames: Object.freeze([]),
      ...(this.state.lastCheckedAt ? { lastCheckedAt: this.state.lastCheckedAt } : {}),
      reason: "The public NVD capability monitor is stopped.",
    });
  }
}

export interface ProductionPublicNvdMcpRuntimeOptions {
  readonly environment?: NodeJS.ProcessEnv;
  readonly now?: () => Date;
  readonly refreshIntervalMs?: number;
}

export interface ProductionPublicNvdMcpBoundary {
  /** Dependency discovery and exact live capability attestation only. */
  readonly runtime: PublicNvdMcpRuntime;
  /**
   * Exact invocation transport with no mission authority of its own. It must
   * remain behind MissionScopedNvdDetailAdapter (or an equally strict reviewed
   * boundary) before any call is reachable from HTTP or an agent runtime.
   */
  readonly client: Pick<PublicNvdMcpToolClient, "getCveDetails">;
  /**
   * Content-free read of the exact attestation held by the same client used
   * for invocation. Consumers can bind readiness without receiving a second
   * transport or any execution authority.
   */
  readonly readAttestation: () => McpCapabilityAttestation | undefined;
}

/**
 * Builds one shared fixed-loopback client for live attestation and the
 * separately gated mission-scoped read-only adapter. Sharing is required:
 * an invocation cannot silently use a second, unattested connection state.
 */
export function createProductionPublicNvdMcpBoundary(
  options: ProductionPublicNvdMcpRuntimeOptions = {},
): ProductionPublicNvdMcpBoundary {
  const environment = options.environment ?? process.env;
  let credentialStore: SystemdCredentialStore | undefined;
  try {
    credentialStore = systemdCredentialStoreFromEnvironment(environment);
  } catch {
    credentialStore = undefined;
  }
  const config = createPublicNvdMcpConnectionConfig();
  const transportFactory = new BoundedStreamableHttpTransportFactory({
    environment,
    // Passing the discovery result explicitly prevents the factory from
    // reparsing an invalid CREDENTIALS_DIRECTORY and keeps startup truthful:
    // the monitor reports unavailable instead of crashing the host process.
    credentialStore,
  });
  const client = new PublicNvdMcpToolClient({
    config,
    transportFactory,
    ...(options.now ? { now: options.now } : {}),
  });
  const runtime = new PublicNvdMcpRuntime({
    client,
    credentialAvailable: () => credentialStore?.has(PUBLIC_NVD_MCP_CREDENTIAL_ID) ?? false,
    ...(options.now ? { now: options.now } : {}),
    ...(options.refreshIntervalMs ? { refreshIntervalMs: options.refreshIntervalMs } : {}),
  });
  return Object.freeze({
    runtime,
    client,
    readAttestation: () => client.currentAttestation,
  });
}

/** Builds the fixed-loopback, systemd-credential-backed monitor used by hosts that expose no lookup route. */
export function createProductionPublicNvdMcpRuntime(
  options: ProductionPublicNvdMcpRuntimeOptions = {},
): PublicNvdMcpRuntime {
  return createProductionPublicNvdMcpBoundary(options).runtime;
}
