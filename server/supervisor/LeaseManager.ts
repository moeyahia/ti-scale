export type LeaseResourceType = "run" | "assignment" | "action";

export interface Lease {
  resourceType: LeaseResourceType;
  resourceId: string;
  ownerId: string;
  acquiredAt: number;
  lastHeartbeatAt: number;
  expiresAt: number;
  version: number;
}

export class LeaseConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LeaseConflictError";
  }
}

function assertTtl(ttlMs: number): void {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new Error("Lease TTL must be positive");
}

export function isLeaseExpired(lease: Readonly<Lease>, now: number): boolean {
  return now >= lease.expiresAt;
}

export function acquireLease(input: {
  existing?: Readonly<Lease>;
  resourceType: LeaseResourceType;
  resourceId: string;
  ownerId: string;
  now: number;
  ttlMs: number;
}): Lease {
  assertTtl(input.ttlMs);
  if (
    input.existing &&
    (input.existing.resourceType !== input.resourceType || input.existing.resourceId !== input.resourceId)
  ) {
    throw new LeaseConflictError("Existing lease refers to a different resource");
  }
  if (input.existing && !isLeaseExpired(input.existing, input.now)) {
    throw new LeaseConflictError(
      `Active ${input.existing.resourceType} lease is owned by ${input.existing.ownerId}`,
    );
  }
  return {
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    ownerId: input.ownerId,
    acquiredAt: input.now,
    lastHeartbeatAt: input.now,
    expiresAt: input.now + input.ttlMs,
    version: (input.existing?.version ?? 0) + 1,
  };
}

export function heartbeatLease(input: {
  lease: Readonly<Lease>;
  ownerId: string;
  expectedVersion: number;
  now: number;
  ttlMs: number;
}): Lease {
  assertTtl(input.ttlMs);
  if (input.lease.ownerId !== input.ownerId || input.lease.version !== input.expectedVersion) {
    throw new LeaseConflictError("Lease owner or version mismatch");
  }
  if (isLeaseExpired(input.lease, input.now)) throw new LeaseConflictError("Cannot heartbeat an expired lease");
  return {
    ...input.lease,
    lastHeartbeatAt: input.now,
    expiresAt: input.now + input.ttlMs,
    version: input.lease.version + 1,
  };
}

export function releaseLease(input: {
  lease: Readonly<Lease>;
  ownerId: string;
  expectedVersion: number;
}): null {
  if (input.lease.ownerId !== input.ownerId || input.lease.version !== input.expectedVersion) {
    throw new LeaseConflictError("Lease owner or version mismatch");
  }
  return null;
}

export type InFlightRecoveryDisposition = "resume_idempotently" | "review_required" | "do_not_repeat";

export function classifyInFlightAction(input: {
  idempotent: boolean;
  destructive: boolean;
  completionKnown: boolean;
}): InFlightRecoveryDisposition {
  if (input.completionKnown) return "do_not_repeat";
  if (input.destructive || !input.idempotent) return "review_required";
  return "resume_idempotently";
}
