import type { EventStreamService } from "../events";
import { getDatabaseHealth, type DatabaseHealth, type SqliteDatabase } from "../db";
import type { SecondBrainService } from "../memory";
import {
  getSecondBrainRuntimeHealth,
  type SecondBrainRuntimeHealth,
} from "../app/SecondBrainRuntimeHealth";

export interface CapabilityLocalHealthSnapshot {
  readonly checkedAt: string;
  readonly database: DatabaseHealth;
  readonly eventStream: {
    readonly started: boolean;
    readonly subscribers: number;
  };
  readonly secondBrain: SecondBrainRuntimeHealth;
}

export interface CapabilityLocalHealthReader {
  read(): CapabilityLocalHealthSnapshot;
}

export interface CapabilitySelfTestRepositoryOptions {
  readonly database: SqliteDatabase;
  readonly eventStream: EventStreamService;
  readonly secondBrain: SecondBrainService;
  /** Read-only Vault sandbox verifier. It must never create or mutate a path. */
  readonly resolveExistingVaultPath?: (vaultPath: string) => string;
  readonly clock?: () => Date;
}

/**
 * Reads the local dependencies already owned by the application. It performs
 * no persistence, network access, provider call, MCP call, Vault write test,
 * or execution authorization. The canonical health readers remain the only
 * source of database, Brain, and persisted Vault truth.
 */
export class CapabilitySelfTestRepository implements CapabilityLocalHealthReader {
  private readonly options: CapabilitySelfTestRepositoryOptions;

  constructor(options: CapabilitySelfTestRepositoryOptions) {
    this.options = options;
  }

  read(): CapabilityLocalHealthSnapshot {
    const checkedAt = (this.options.clock ?? (() => new Date()))().toISOString();
    return {
      checkedAt,
      database: getDatabaseHealth(this.options.database),
      eventStream: {
        started: this.options.eventStream.isStarted,
        subscribers: this.options.eventStream.subscriptionCount,
      },
      secondBrain: getSecondBrainRuntimeHealth(
        this.options.database,
        this.options.secondBrain,
        {
          ...(this.options.resolveExistingVaultPath
            ? { resolveExistingVaultPath: this.options.resolveExistingVaultPath }
            : {}),
        },
      ),
    };
  }
}
