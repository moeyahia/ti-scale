import { ATTACK_CENTRIC_REUSABLE_NODE_TYPES } from "../memory/types";
import {
  ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY,
  ATTACK_BRAIN_ATLAS_NODE_TYPES,
  assertAttackBrainAtlasMappingRegistryComplete as assertSharedRegistryComplete,
  assertOperatorProfileBrainAtlasMappingRegistryComplete,
} from "../../shared/AttackBrainAtlasMappingRegistry";

export * from "../../shared/AttackBrainAtlasMappingRegistry";

/** Server-side drift gate against the canonical reusable-memory registry. */
export function assertAttackBrainAtlasMappingRegistryComplete(): void {
  assertSharedRegistryComplete();
  assertOperatorProfileBrainAtlasMappingRegistryComplete();
  const memoryTypes = new Set<string>(ATTACK_CENTRIC_REUSABLE_NODE_TYPES);
  const atlasTypes = new Set<string>(ATTACK_BRAIN_ATLAS_NODE_TYPES);
  const missing = [...memoryTypes].filter((value) => !atlasTypes.has(value));
  const extra = [...atlasTypes].filter((value) => !memoryTypes.has(value));
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(`Brain Atlas and reusable-memory registries differ (missing: ${missing.join(", ") || "none"}; extra: ${extra.join(", ") || "none"})`);
  }
  if (ATTACK_BRAIN_ATLAS_MAPPING_REGISTRY.length !== ATTACK_CENTRIC_REUSABLE_NODE_TYPES.length) {
    throw new Error("Brain Atlas mapping registry cardinality differs from reusable memory");
  }
}
