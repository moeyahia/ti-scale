import type { MemoryEdgeSummary, MemoryNodeSummary } from "../domain/types/brain";
import { compactGraphLayout, layoutGraph, relaxGraphLayout } from "../features/brain/graphUtils";

interface LayoutRequest {
  requestId: number;
  nodes: MemoryNodeSummary[];
  edges: MemoryEdgeSummary[];
  width: number;
  height: number;
  compact: boolean;
  physics: boolean;
}

self.onmessage = (event: MessageEvent<LayoutRequest>) => {
  const { requestId, nodes, edges, width, height, compact, physics } = event.data;
  const initial = layoutGraph(nodes, width, height);
  const weighted = physics ? relaxGraphLayout(initial, edges, width, height) : initial;
  self.postMessage({ requestId, points: compact ? compactGraphLayout(weighted, width, height) : weighted });
};
