export const TI_SCALE_BROWSER_NAMESPACE = "ti-scale" as const;

export const BROWSER_STORAGE_KEYS = {
  eventResume: `${TI_SCALE_BROWSER_NAMESPACE}.events.last-event-id`,
  brainGraphRoot: `${TI_SCALE_BROWSER_NAMESPACE}.brain.graph-root`,
  brainSavedViews: `${TI_SCALE_BROWSER_NAMESPACE}.brain.saved-graph-views.v1`,
  brainPinnedPositions: `${TI_SCALE_BROWSER_NAMESPACE}.brain.pinned-graph-positions.v1`,
} as const;

export const BROWSER_CHANNEL_NAMES = {
  runtimeEvents: `${TI_SCALE_BROWSER_NAMESPACE}.runtime-events`,
} as const;

export const BROWSER_CACHE_NAMES = {
  shell: `${TI_SCALE_BROWSER_NAMESPACE}.shell`,
  media: `${TI_SCALE_BROWSER_NAMESPACE}.media`,
} as const;
