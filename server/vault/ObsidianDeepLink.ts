import { basename } from "node:path";
import type { VaultConnection } from "./types";

function cleanRelativeNotePath(relativePath: string): string {
  if (
    !relativePath.trim()
    || relativePath.includes("\0")
    || relativePath.startsWith("/")
    || relativePath.includes("\\")
  ) {
    throw new TypeError("Obsidian note path must be a safe relative path");
  }
  const segments = relativePath.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new TypeError("Obsidian note path traversal is not permitted");
  }
  if (segments.some((segment) => segment.toLowerCase() === ".obsidian")) {
    throw new Error("Ti-Scale does not address Obsidian settings paths");
  }
  return relativePath.replace(/\.md$/iu, "");
}

/** Build a portable Obsidian URI without exposing the server's absolute path. */
export function obsidianDeepLink(
  connection: Pick<VaultConnection, "vaultPath">,
  relativePath?: string,
): string {
  const vaultName = basename(connection.vaultPath).trim();
  if (!vaultName || vaultName === "." || vaultName === "..") {
    throw new Error("Connected vault has no portable Obsidian name");
  }
  const query = new URLSearchParams({ vault: vaultName });
  if (relativePath) query.set("file", cleanRelativeNotePath(relativePath));
  return `obsidian://open?${query.toString()}`;
}
