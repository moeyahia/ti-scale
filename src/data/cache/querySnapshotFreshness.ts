import { useEffect, useState } from "react";

export function querySnapshotExpired(
  updatedAt: number | null | undefined,
  maximumAgeMs: number,
  now = Date.now(),
): boolean {
  if (updatedAt === null || updatedAt === undefined) return false;
  if (!Number.isFinite(updatedAt) || updatedAt <= 0) return true;
  return now - updatedAt >= maximumAgeMs;
}

export function useQuerySnapshotExpired(
  updatedAt: number | null | undefined,
  maximumAgeMs: number,
): boolean {
  const [expired, setExpired] = useState(() =>
    querySnapshotExpired(updatedAt, maximumAgeMs));

  useEffect(() => {
    const nextExpired = querySnapshotExpired(updatedAt, maximumAgeMs);
    setExpired(nextExpired);
    if (
      nextExpired
      || updatedAt === null
      || updatedAt === undefined
      || updatedAt <= 0
    ) return;

    const remainingMs = Math.max(0, updatedAt + maximumAgeMs - Date.now());
    const timer = globalThis.setTimeout(() => setExpired(true), remainingMs + 1);
    return () => globalThis.clearTimeout(timer);
  }, [maximumAgeMs, updatedAt]);

  return expired;
}
