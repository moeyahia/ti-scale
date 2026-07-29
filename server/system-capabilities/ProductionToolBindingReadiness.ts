import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { isAbsolute } from "node:path";
import type { RuntimeSourceManifests } from "../domain";
import {
  TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
  ToolBindingRegistry,
} from "./ToolBindingRegistry";
import {
  ToolBindingReadinessRunner,
  type ToolBindingReadinessSnapshot,
} from "./ToolBindingReadinessRunner";
import {
  ToolExecutionPreflightService,
  toolExecutionPreflightBindingSha256,
} from "./ToolExecutionPreflight";
import { exactManifestMcpServerIds } from "./McpInventoryIntegrity";

const MAXIMUM_REGISTRY_BYTES = 512 * 1_024;

export interface ProductionToolBindingReadiness {
  readonly runner: ToolBindingReadinessRunner;
  readonly configured: boolean;
  /**
   * Returns the canonical manifest view consumed by intake and mission
   * readiness. Remote tools remain governed by their MCP attestations; local
   * tools are withdrawn unless the registry and expiring isolated probe agree.
   */
  projectManifests(manifests: RuntimeSourceManifests, now?: Date): RuntimeSourceManifests;
  assertCompleteInitialWave(snapshot: ToolBindingReadinessSnapshot): void;
}

function registryDocument(path: string | undefined): unknown {
  const configured = path?.trim();
  if (!configured) {
    return {
      schemaVersion: TOOL_BINDING_REGISTRY_SCHEMA_VERSION,
      registryVersion: "empty-v1",
      bindings: [],
    };
  }
  if (!isAbsolute(configured)) {
    throw new Error("TI_SCALE_TOOL_BINDING_REGISTRY_PATH must be an absolute path");
  }
  let pathMetadata: ReturnType<typeof lstatSync>;
  try {
    pathMetadata = lstatSync(configured, { bigint: true });
  } catch {
    throw new Error("The configured tool binding registry is not readable");
  }
  if (pathMetadata.isSymbolicLink() || !pathMetadata.isFile()) {
    throw new Error("The configured tool binding registry must be a regular non-symlink file");
  }
  const size = Number(pathMetadata.size);
  const mode = Number(pathMetadata.mode & 0o7777n);
  const owner = Number(pathMetadata.uid);
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  if (!Number.isSafeInteger(size) || size < 2 || size > MAXIMUM_REGISTRY_BYTES) {
    throw new Error(`The configured tool binding registry must be between 2 and ${MAXIMUM_REGISTRY_BYTES} bytes`);
  }
  if ((owner !== 0 && owner !== currentUid) || (mode & 0o022) !== 0) {
    throw new Error("The configured tool binding registry must have a trusted owner and must not be group/world writable");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(configured, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(descriptor, { bigint: true });
    const openedMode = Number(opened.mode & 0o7777n);
    const openedOwner = Number(opened.uid);
    if (!opened.isFile()
      || opened.dev !== pathMetadata.dev
      || opened.ino !== pathMetadata.ino
      || opened.size !== pathMetadata.size
      || opened.mode !== pathMetadata.mode
      || opened.uid !== pathMetadata.uid
      || opened.gid !== pathMetadata.gid
      || opened.ctimeNs !== pathMetadata.ctimeNs
      || (openedOwner !== 0 && openedOwner !== currentUid)
      || (openedMode & 0o022) !== 0) {
      throw new Error("registry_identity_changed");
    }
    const source = readFileSync(descriptor, "utf8");
    const after = fstatSync(descriptor, { bigint: true });
    if (after.dev !== opened.dev
      || after.ino !== opened.ino
      || after.size !== opened.size
      || after.mode !== opened.mode
      || after.uid !== opened.uid
      || after.gid !== opened.gid
      || after.mtimeNs !== opened.mtimeNs
      || after.ctimeNs !== opened.ctimeNs) {
      throw new Error("registry_identity_changed");
    }
    return JSON.parse(source) as unknown;
  } catch {
    throw new Error("The configured tool binding registry is not stable, safely readable, and valid JSON");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

/**
 * Loads only explicitly reviewed local executable probes. Remote/MCP tools use
 * their own inventory attestation, while every available local runtime tool is
 * required to have exactly one binding before startup can claim readiness.
 */
export function createProductionToolBindingReadiness(options: Readonly<{
  manifests: RuntimeSourceManifests;
  registryPath?: string;
  /** Injectable only for a technically isolated worker or deterministic tests. */
  preflight?: ToolExecutionPreflightService;
  clock?: () => Date;
}>): ProductionToolBindingReadiness {
  const registry = new ToolBindingRegistry(
    registryDocument(options.registryPath),
    options.manifests,
  );
  const missing = options.manifests.tools.filter((tool) =>
    tool.available
    && tool.mcpServerId === undefined
    && registry.resolve(tool.id) === undefined);
  if (missing.length > 0) {
    throw new Error(
      `${missing.length} available local runtime tool binding${missing.length === 1 ? " is" : "s are"} missing from the reviewed registry`,
    );
  }
  const runner = new ToolBindingReadinessRunner(
    registry,
    options.preflight ?? new ToolExecutionPreflightService(),
    options.clock ?? (() => new Date()),
  );
  return Object.freeze({
    runner,
    configured: Boolean(options.registryPath?.trim()),
    projectManifests(manifests: RuntimeSourceManifests, now: Date = new Date()) {
      const aligned = registry.isAlignedWith(manifests);
      const exactMcpServers = exactManifestMcpServerIds(manifests);
      return {
        ...manifests,
        tools: manifests.tools.map((tool) => {
          if (tool.mcpServerId !== undefined) {
            const exactBinding = aligned && exactMcpServers.has(tool.mcpServerId);
            if (exactBinding) return tool;
            return {
              ...tool,
              available: false,
              dependencies: [
                ...(tool.dependencies ?? []).filter(({ id }) => id !== "exact-mcp-tool-identity"),
                { id: "exact-mcp-tool-identity", ready: false },
              ],
            };
          }
          const binding = registry.resolve(tool.id);
          const receipt = runner.readReceipt(tool.id);
          const expiry = receipt ? Date.parse(receipt.expiresAt) : Number.NaN;
          const isolated = receipt?.probeBoundary.networkIsolationEnforced === true
            && receipt.probeBoundary.filesystemWriteIsolationEnforced === true
            && receipt.probeBoundary.immutableSnapshotExecutionEnforced === true;
          const identityBound = receipt?.executableIdentity !== null
            && receipt?.executableIdentity !== undefined
            && /^[a-f0-9]{64}$/u.test(receipt.executableIdentity.sha256);
          const current = Number.isFinite(expiry) && expiry > now.getTime();
          const bindingMatched = binding !== undefined
            && receipt?.registryBindingSha256 === binding.bindingSha256
            && receipt.runtimeManifestSha256 === registry.descriptor.runtimeManifestSha256
            && receipt.preflightBindingSha256 === toolExecutionPreflightBindingSha256(
              registry.toPreflightSpec(tool.id)!,
            );
          const readinessAccepted = tool.available
            && aligned
            && bindingMatched
            && receipt?.status === "ready"
            && receipt.code === "ready"
            && current
            && isolated
            && identityBound;
          return {
            ...tool,
            available: readinessAccepted,
            dependencies: [
              ...(tool.dependencies ?? []).filter(({ id }) => id !== "local-tool-binding-readiness"),
              { id: "local-tool-binding-readiness", ready: readinessAccepted },
            ],
          };
        }),
      };
    },
    assertCompleteInitialWave(snapshot: ToolBindingReadinessSnapshot): void {
      if (!snapshot.accounting.complete
        || snapshot.accounting.attempted !== snapshot.accounting.registered
        || snapshot.accounting.reported !== snapshot.accounting.registered
        || snapshot.accounting.unexpected !== 0) {
        throw new Error("The initial local tool readiness wave did not produce complete registry accounting");
      }
      if (snapshot.accounting.registered > 0 && !snapshot.accounting.current) {
        throw new Error("The initial local tool readiness wave did not produce current receipts");
      }
    },
  });
}
