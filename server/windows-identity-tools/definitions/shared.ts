import type { WindowsIdentityToolDefinition } from "../types";

export const identityExecution = (
  timeoutMs: number,
  maximumOutputBytes: number,
): WindowsIdentityToolDefinition["execution"] => Object.freeze({
  directArgv: true,
  shell: false,
  readOnlyTargetOperation: true,
  timeoutMs,
  maximumOutputBytes,
  terminationGraceMs: 750,
  maximumConcurrency: 1,
  workspaceWrites: "sandbox_workspace_only",
  credentialDelivery: "opaque_reference_to_private_files",
});

export const identityProbe = (
  arguments_: readonly string[],
  expectedExitCodes: readonly number[] = [0],
): WindowsIdentityToolDefinition["probe"] => Object.freeze({
  arguments: Object.freeze([...arguments_]),
  expectedExitCodes: Object.freeze([...expectedExitCodes]),
  timeoutMs: 3_000,
  maximumOutputBytes: 32 * 1_024,
  ttlMs: 60_000,
  targetContact: false,
});
