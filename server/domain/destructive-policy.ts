import type { DestructiveActionPolicy } from "./action-class-registry";

export interface DestructiveAuthorizationResult {
  readonly allowed: boolean;
  readonly reason: "non_destructive" | "policy_not_bounded" | "target_not_bounded" | "bounded_lab_target";
}

/** Unknown and legacy policy strings intentionally fail closed. */
export function evaluateDestructiveAuthorization(input: {
  readonly destructive: boolean;
  readonly policy: string | undefined;
  readonly target: string;
  readonly boundedTargets: readonly string[];
}): DestructiveAuthorizationResult {
  if (!input.destructive) return { allowed: true, reason: "non_destructive" };
  const policy = input.policy?.trim().toLowerCase() as DestructiveActionPolicy | undefined;
  if (policy !== "bounded_lab_only") return { allowed: false, reason: "policy_not_bounded" };
  const target = input.target.trim();
  const bounded = new Set(input.boundedTargets.map((value) => value.trim()).filter(Boolean));
  return bounded.has(target)
    ? { allowed: true, reason: "bounded_lab_target" }
    : { allowed: false, reason: "target_not_bounded" };
}
