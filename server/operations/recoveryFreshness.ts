/** Runtime fleet projection normally refreshes every 15 seconds. Recovery
 * reassignment accepts an agent heartbeat for at most four projection cycles. */
export const DEFAULT_RECOVERY_AGENT_HEARTBEAT_MAX_AGE_MS = 60_000;

export function recoveryAgentHeartbeatMaxAge(value?: number): number {
  const candidate = value ?? DEFAULT_RECOVERY_AGENT_HEARTBEAT_MAX_AGE_MS;
  if (!Number.isSafeInteger(candidate) || candidate < 5_000 || candidate > 15 * 60_000) {
    throw new RangeError("Recovery agent heartbeat max age must be between 5 seconds and 15 minutes");
  }
  return candidate;
}

export function isRecoveryAgentHeartbeatFresh(
  heartbeatAt: string | null,
  now: string,
  maxAgeMs = DEFAULT_RECOVERY_AGENT_HEARTBEAT_MAX_AGE_MS,
): boolean {
  if (!heartbeatAt) return false;
  const heartbeat = Date.parse(heartbeatAt);
  const current = Date.parse(now);
  const age = current - heartbeat;
  return Number.isFinite(heartbeat) && Number.isFinite(current) && age >= 0 && age <= maxAgeMs;
}
