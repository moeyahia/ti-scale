import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve, sep } from "node:path";
import {
  WindowsIdentityBoundaryError,
  type WindowsIdentityCredentialMaterialBinding,
  type WindowsIdentityCredentialMaterialResolver,
  type WindowsIdentityCredentialView,
} from "./types";

const REFERENCE_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;
const VIEW_FILE: Readonly<Record<WindowsIdentityCredentialView, string>> = Object.freeze({
  samba_auth_file: "samba-auth",
  username_file: "username",
  password_file: "password",
  ldap_bind_identity: "ldap-bind-identity",
});
const MAX_FILE_BYTES = 64 * 1_024;
const MAX_ACTIVE_BINDINGS = 1_024;

function denied(message: string): never {
  throw new WindowsIdentityBoundaryError(
    "windows_identity_credential_binding_changed",
    "policy_denied",
    message,
    false,
  );
}

async function trustedDirectory(path: string): Promise<string> {
  const metadata = await lstat(path).catch(() => undefined);
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  if (!metadata || metadata.isSymbolicLink() || !metadata.isDirectory()
    || (metadata.uid !== 0 && metadata.uid !== currentUid)
    || (metadata.mode & 0o022) !== 0) {
    denied("The opaque credential bundle directory is missing, symlinked, untrusted, or writable by another account.");
  }
  return realpath(path);
}

async function trustedView(path: string, bundleRoot: string): Promise<string> {
  const metadata = await lstat(path).catch(() => undefined);
  const currentUid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  if (!metadata || metadata.isSymbolicLink() || !metadata.isFile()
    || (metadata.uid !== 0 && metadata.uid !== currentUid)
    || (metadata.mode & 0o077) !== 0
    || metadata.size < 1 || metadata.size > MAX_FILE_BYTES) {
    denied("A required opaque credential view is missing, symlinked, has unsafe permissions, or exceeds the private-file limit.");
  }
  const canonical = await realpath(path);
  if (!canonical.startsWith(`${bundleRoot}${sep}`)) {
    denied("A required opaque credential view resolves outside its configured bundle.");
  }
  return canonical;
}

/**
 * Resolves only opaque IDs into deployment-owned private files. It never reads
 * or returns credential content, and its receipt grants no authorization.
 */
export class SystemdWindowsIdentityCredentialResolver
implements WindowsIdentityCredentialMaterialResolver {
  readonly root: string;
  private readonly clock: () => Date;
  private readonly bindings = new Map<string, WindowsIdentityCredentialMaterialBinding>();

  constructor(root: string, clock: () => Date = () => new Date()) {
    if (!isAbsolute(root) || resolve(root) === resolve(sep)) {
      throw new Error("Windows/identity credential root must be a non-root absolute path");
    }
    this.root = resolve(root);
    this.clock = clock;
  }

  async readiness(): Promise<boolean> {
    try {
      await trustedDirectory(this.root);
      return true;
    } catch {
      return false;
    }
  }

  async resolve(input: Parameters<WindowsIdentityCredentialMaterialResolver["resolve"]>[0]): Promise<WindowsIdentityCredentialMaterialBinding> {
    if (input.reference.kind !== "systemd_credential_bundle"
      || !REFERENCE_ID.test(input.reference.id)
      || !input.runId || !/^[a-f0-9]{64}$/u.test(input.actionFingerprint)
      || input.requiredViews.length < 1
      || new Set(input.requiredViews).size !== input.requiredViews.length) {
      denied("The opaque credential request is not canonical for this exact run and action.");
    }
    const root = await trustedDirectory(this.root);
    const bundle = await trustedDirectory(join(root, input.reference.id));
    if (!bundle.startsWith(`${root}${sep}`)) {
      denied("The opaque credential bundle resolves outside the configured private root.");
    }
    const files: Partial<Record<WindowsIdentityCredentialView, string>> = {};
    for (const view of input.requiredViews) {
      const fileName = VIEW_FILE[view];
      if (!fileName) denied("The requested opaque credential view is unsupported.");
      files[view] = await trustedView(join(bundle, fileName), bundle);
    }
    const now = this.clock();
    const key = [
      input.reference.id,
      input.runId,
      input.actionFingerprint,
      [...input.requiredViews].sort().join(","),
    ].join("\u0000");
    const existing = this.bindings.get(key);
    if (existing
      && Date.parse(existing.receipt.expiresAt) > now.getTime()
      && JSON.stringify(existing.files) === JSON.stringify(files)) {
      return existing;
    }
    for (const [bindingKey, binding] of this.bindings) {
      if (Date.parse(binding.receipt.expiresAt) <= now.getTime()) this.bindings.delete(bindingKey);
    }
    if (this.bindings.size >= MAX_ACTIVE_BINDINGS) {
      denied("The private credential binding cache is full; wait for existing short-lived bindings to expire before retrying.");
    }
    const binding = Object.freeze({
      receipt: Object.freeze({
        schemaVersion: "ti-scale.windows-identity-credential-binding.v1",
        referenceId: input.reference.id,
        runId: input.runId,
        actionFingerprint: input.actionFingerprint,
        availableViews: Object.freeze([...input.requiredViews]),
        mountedReadOnly: true,
        privateToProcess: true,
        expiresAt: new Date(now.getTime() + 30_000).toISOString(),
        grantsAuthorization: false,
      }),
      files: Object.freeze(files),
    });
    this.bindings.set(key, binding);
    return binding;
  }
}
