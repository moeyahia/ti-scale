export const TI_SCALE_BROWSER_NAMESPACE = "ti-scale" as const;

export const BROWSER_STORAGE_KEYS = {
  eventResume: `${TI_SCALE_BROWSER_NAMESPACE}.events.last-event-id`,
  brainGraphRoot: `${TI_SCALE_BROWSER_NAMESPACE}.brain.graph-root`,
  brainSavedViews: `${TI_SCALE_BROWSER_NAMESPACE}.brain.saved-graph-views.v1`,
  brainPinnedPositions: `${TI_SCALE_BROWSER_NAMESPACE}.brain.pinned-graph-positions.v1`,
  recoveryMutationIntentPrefix: `${TI_SCALE_BROWSER_NAMESPACE}.recovery.mutation-intent.v1`,
  researchPromotionIntentPrefix: `${TI_SCALE_BROWSER_NAMESPACE}.research.promotion-intent.v1`,
} as const;

export const BROWSER_CHANNEL_NAMES = {
  runtimeEvents: `${TI_SCALE_BROWSER_NAMESPACE}.runtime-events`,
} as const;

export const BROWSER_CACHE_NAMES = {
  shell: `${TI_SCALE_BROWSER_NAMESPACE}.shell`,
  media: `${TI_SCALE_BROWSER_NAMESPACE}.media`,
} as const;

export function clearBrowserStoragePrefix(
  storage: Pick<Storage, "key" | "length" | "removeItem">,
  prefix: string,
): void {
  const matches: string[] = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (key?.startsWith(prefix)) matches.push(key);
  }
  matches.forEach((key) => storage.removeItem(key));
}
