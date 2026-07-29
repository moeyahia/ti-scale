import { guidedCommanderApi } from "../api/guidedCommander";
import { useQuery, type QueryResult } from "../cache/QueryProvider";
import type { GuidedTranscript } from "../../domain/types/guidedCommander";

/** Event-stream invalidation uses the same `guided-mission:` cache prefix. */
export function useGuidedTranscript(
  missionId: string,
  runId: string,
  stepId?: string,
): QueryResult<GuidedTranscript> {
  const key = `guided-mission:${missionId}:commander:${runId}:${stepId ?? "all"}`;
  return useQuery(
    key,
    (signal) => guidedCommanderApi.transcript(
      missionId,
      { runId, ...(stepId ? { stepId } : {}), limit: 200 },
      signal,
    ),
    { staleTime: 10_000 },
  );
}
