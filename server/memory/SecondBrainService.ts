import type {
  ContextPack,
  ContextPackItemDisposition,
  CreateMemoryCandidateInput,
  CreateMemoryEdgeInput,
  CreateMemoryNodeInput,
  ForgetResult,
  MemoryCandidate,
  MemoryEdge,
  MemoryNode,
  RetrievalPolicy,
  RetrievedMemory,
} from "./types";
import { MemoryRepository } from "./MemoryRepository";
import { MemoryRetrievalService } from "./MemoryRetrievalService";
import {
  getMemoryControlPolicy,
  memoryCandidateAllowed,
} from "./MemoryControlPolicy";

/** Application-facing façade. HTTP, jobs, and provider adapters can share it. */
export class SecondBrainService {
  readonly repository: MemoryRepository;
  readonly retrieval: MemoryRetrievalService;

  constructor(repository: MemoryRepository) {
    this.repository = repository;
    this.retrieval = new MemoryRetrievalService(repository);
  }

  createOperationalMemory(input: CreateMemoryNodeInput): MemoryNode {
    const control = getMemoryControlPolicy(this.repository.database());
    if (!control.enabled || (!control.operationalMemoryEnabled && input.nodeType !== "preference")) {
      throw new Error("Second Brain retention is disabled by operator memory controls");
    }
    if (input.nodeType === "preference" && (
      control.personalPreferencePolicy === "disabled" ||
      input.authorType !== "operator" ||
      input.confirmationState !== "confirmed"
    )) {
      throw new Error("Personal preferences must be deliberately confirmed by the operator or retained as candidates");
    }
    return this.repository.createNode(input);
  }

  createRelationship(input: CreateMemoryEdgeInput): MemoryEdge {
    const control = getMemoryControlPolicy(this.repository.database());
    if (!control.enabled) throw new Error("Second Brain retention is disabled by operator memory controls");
    return this.repository.createEdge(input);
  }

  proposeMemory(input: CreateMemoryCandidateInput): MemoryCandidate {
    const control = getMemoryControlPolicy(this.repository.database());
    if (!memoryCandidateAllowed(control, input.nodeType)) {
      throw new Error(input.nodeType === "preference"
        ? "Personal preference learning is disabled by operator memory controls"
        : "Operational memory retention is disabled by operator memory controls");
    }
    return this.repository.createCandidate(input);
  }

  confirmCandidate(
    candidateId: string,
    reviewer: string,
    edits: Parameters<MemoryRepository["confirmCandidate"]>[2] = {},
  ): MemoryNode {
    const candidate = this.repository.requireCandidate(candidateId);
    const control = getMemoryControlPolicy(this.repository.database());
    if (!memoryCandidateAllowed(control, candidate.nodeType)) {
      throw new Error("This memory category is disabled by operator memory controls");
    }
    return this.repository.confirmCandidate(candidateId, reviewer, edits);
  }

  rejectAndDoNotRelearn(candidateId: string, reviewer: string, reason: string): string {
    return this.repository.rejectCandidateAndSuppress(candidateId, reviewer, reason);
  }

  rejectCandidate(candidateId: string, reviewer: string, reason: string): MemoryCandidate {
    return this.repository.rejectCandidate(candidateId, reviewer, reason);
  }

  retrieve(query: string, policy: RetrievalPolicy): readonly RetrievedMemory[] {
    return this.retrieval.retrieve(query, policy);
  }

  retrieveAndPersistContext(input: {
    readonly query: string;
    readonly queryRedacted?: string;
    readonly policy: RetrievalPolicy;
    readonly purpose: string;
    readonly createdBy: string;
    readonly missionId?: string;
    readonly runId?: string;
    readonly stepId?: string;
    readonly actionId?: string;
    readonly messageId?: string;
  }): ContextPack {
    const startedAt = performance.now();
    const items = this.retrieval.retrieve(input.query, input.policy);
    return this.repository.persistContextPack({
      missionId: input.missionId,
      runId: input.runId,
      stepId: input.stepId,
      actionId: input.actionId,
      messageId: input.messageId,
      journey: input.policy.journey,
      purpose: input.purpose,
      queryRedacted: input.queryRedacted,
      scopePolicy: input.policy,
      contextBudget: input.policy.contextBudget,
      retrievalMetrics: {
        durationMs: Number((performance.now() - startedAt).toFixed(3)),
        retrievedCount: items.length,
        signals: [...new Set(items.flatMap((item) => item.signals))],
      },
      createdBy: input.createdBy,
      items,
    });
  }

  recordContextUse(packId: string, disposition: ContextPackItemDisposition): void {
    this.repository.setContextItemDisposition(packId, disposition);
  }

  forget(nodeId: string, actor: string, reason?: string): ForgetResult {
    return this.repository.forgetNode(nodeId, actor, reason);
  }
}
