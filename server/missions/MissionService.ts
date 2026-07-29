import { autonomousContractHash, hashCanonical } from "./canonical";
import { isIP } from "node:net";
import {
  BrainContextHookError,
  CanonicalMissionMemoryGraph,
  type BrainContextService,
  retrieveMissionBrainContext,
} from "../brain-runtime";
import { AutonomousReadinessError } from "./errors";
import {
  AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS,
  AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA,
  AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS,
  autonomousMaterialObjectiveRequirements,
  buildEvidenceTypeRegistry,
  buildRuntimeCapabilityProjection,
  emptyRuntimeSourceManifests,
  isEvidenceTypeId,
  resolveAutonomousOutcomeProfile,
  type RuntimeSourceManifests,
} from "../domain";
import { MissionApiError } from "./errors";
import { MissionRepository, type ListMissionsOptions } from "./MissionRepository";
import { OverviewRepository } from "./OverviewRepository";
import { ReadinessService } from "./ReadinessService";
import { applyAutonomousIntakePreferenceDefaults } from "./AutonomousIntakePreferenceDefaults";
import {
  ModelConfigurationError,
  resolveAutonomousPlanningSelection,
  type ModelConfigurationService,
} from "../model-config";
import type {
  AutonomousMissionPreflight,
  AutonomousMissionRequest,
  CreatedMission,
  MissionCreateRequest,
  MissionIntakeContextBinding,
  MissionListPage,
  OverviewSnapshot,
} from "./types";

type AutonomousModelConfigurationBoundary = Pick<
  ModelConfigurationService,
  "resolveAutonomousAssignments"
  | "validateAutonomousAssignments"
  | "pinExactAutonomousAssignments"
> & Partial<Pick<
  ModelConfigurationService,
  "validateAutonomousPlanningSelection"
  | "pinExactAutonomousPlanningSelection"
  | "pinSelectedSpecialistAdvisoryAssignments"
>>;

function missionIntakeQuery(request: MissionCreateRequest): string {
  const targets = request.journey === "autonomous"
    ? request.authorization.allowedTargets
    : request.target ? [request.target] : [];
  return [
    `${request.journey} authorized mission intake`,
    request.title,
    request.objective,
    ...targets,
  ].join("\n");
}

function redactedMissionIntakeQuery(request: MissionCreateRequest): string {
  const targetCount = request.journey === "autonomous"
    ? request.authorization.allowedTargets.length
    : request.target ? 1 : 0;
  return `${request.journey} mission intake; ${targetCount} authorized target reference${targetCount === 1 ? "" : "s"}; objective and target identifiers retained locally only`;
}

function readinessSummary(checks: AutonomousMissionPreflight["readiness"]["checks"]): AutonomousMissionPreflight["readiness"] {
  const status = checks.some((check) => check.status === "fail")
    ? "blocked"
    : checks.some((check) => check.status === "warn")
      ? "degraded"
      : "ready";
  const points = checks.reduce(
    (total, check) => total + (check.status === "pass" ? 100 : check.status === "warn" ? 65 : 0),
    0,
  );
  return {
    status,
    score: checks.length === 0 ? 0 : Math.round(points / checks.length),
    checks,
  };
}

function requiredEvidenceReadiness(
  request: AutonomousMissionRequest,
  readRuntimeManifests: () => RuntimeSourceManifests,
): AutonomousMissionPreflight["readiness"]["checks"][number] {
  const selectedIds = [...new Set(request.contract.evidenceRequirements.filter(isEvidenceTypeId))];
  if (selectedIds.length === 0) {
    return {
      id: "contract_evidence_capability",
      label: "Required evidence capability",
      status: "pass",
      journeys: ["autonomous"],
      impact: "No registry-backed evidence type requires a runtime producer in this contract. Immutable finding-evidence rules remain enforced independently.",
    };
  }

  try {
    const registry = buildEvidenceTypeRegistry(
      buildRuntimeCapabilityProjection(readRuntimeManifests()),
    );
    const impossible = selectedIds
      .map((id) => registry.types[id])
      .filter(({ capability }) => capability.availability !== "supported");
    if (impossible.length > 0) {
      return {
        id: "contract_evidence_capability",
        label: "Required evidence capability",
        status: "fail",
        journeys: ["autonomous"],
        impact: `The signed contract requires evidence the current runtime cannot produce: ${impossible.map((item) => `${item.label} (${item.capability.availability})`).join(", ")}. Autonomous cannot promise completion while these remain required.`,
        remediation: "Reconnect or register an attributable runtime producer for each required evidence type, or remove that mission requirement and rerun preflight. Verified findings still require their immutable evidence regardless of mission preferences.",
      };
    }
    return {
      id: "contract_evidence_capability",
      label: "Required evidence capability",
      status: "pass",
      journeys: ["autonomous"],
      impact: `${selectedIds.length} registry-backed required evidence type${selectedIds.length === 1 ? " has" : "s have"} an available runtime producer. Immutable finding-evidence rules remain enforced independently.`,
    };
  } catch {
    return {
      id: "contract_evidence_capability",
      label: "Required evidence capability",
      status: "fail",
      journeys: ["autonomous"],
      impact: "The runtime evidence registry could not be verified, so Autonomous cannot promise the selected required evidence.",
      remediation: "Repair and re-attest the runtime capability registry, then rerun preflight. Do not remove immutable evidence required to verify findings.",
    };
  }
}

function exactExploitValidationContractReadiness(
  request: AutonomousMissionRequest,
): AutonomousMissionPreflight["readiness"]["checks"] {
  if (!request.contract.allowedActionClasses.includes("exploit_validation")) return [];
  const disposableEnvironment = (
    request.authorization.environmentClassification === "htb"
    || request.authorization.environmentClassification === "ctf"
    || request.authorization.environmentClassification === "local_disposable_lab"
  );
  const boundedTargets = request.contract.boundedDestructiveTargets ?? [];
  const exactHost = (target: string): boolean => {
    const normalized = target.trim();
    if (isIP(normalized) > 0) return true;
    if (!normalized || normalized.includes("/") || normalized.includes("://") || normalized.includes(":")) return false;
    return normalized.length <= 253 && normalized.split(".").every((part) =>
      /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(part));
  };
  const exactBoundedTargets = boundedTargets.length > 0
    && boundedTargets.every((target) =>
      exactHost(target) && request.authorization.allowedTargets.includes(target));
  const labBoundaryReady = (
    disposableEnvironment
    && request.contract.destructivePolicy === "bounded_lab_only"
    && exactBoundedTargets
  );
  const verifiedAttackMemoryReady = request.contract.memoryScopes.includes("verified_attack_knowledge");
  return [
    labBoundaryReady
      ? {
          id: "contract_exploit_disposable_lab_boundary",
          label: "Exact disposable-lab exploit boundary",
          status: "pass",
          journeys: ["autonomous"],
          impact: "Exploit validation is restricted to an exact authorized host in an explicitly classified disposable lab.",
        }
      : {
          id: "contract_exploit_disposable_lab_boundary",
          label: "Exact disposable-lab exploit boundary",
          status: "fail",
          journeys: ["autonomous"],
          impact: "Exploit validation cannot run against an ordinary host, broad network, URL, or environment that was not explicitly classified as disposable.",
          remediation: "Classify the mission as Hack The Box, CTF, or Local disposable lab; choose Named disposable lab targets only; then bind the exact authorized host or IP.",
        },
    verifiedAttackMemoryReady
      ? {
          id: "contract_exploit_verified_attack_memory",
          label: "Verified attack-safety memory",
          status: "pass",
          journeys: ["autonomous"],
          impact: "The core agent may retrieve verified attack-safety knowledge and known-hazard gates before the represented attempt.",
        }
      : {
          id: "contract_exploit_verified_attack_memory",
          label: "Verified attack-safety memory",
          status: "fail",
          journeys: ["autonomous"],
          impact: "Exploit validation requires the verified attack-knowledge scope so known hazards and mandatory recovery gates cannot be bypassed.",
          remediation: "Enable Verified attack safety knowledge in the Second Brain contract before launch.",
        },
  ];
}

function exactDnsOutcomeReadiness(
  request: AutonomousMissionRequest,
): AutonomousMissionPreflight["readiness"]["checks"] {
  if (
    request.contract.allowedActionClasses.length !== 1
    || request.contract.allowedActionClasses[0] !== "dns_domain_certificate_discovery"
  ) return [];

  const unsupportedCriteria = request.successCriteria.filter(
    (criterion) => criterion !== AUTONOMOUS_DNS_A_SUCCESS_CRITERION,
  );
  const nonDomainTargets = request.authorization.allowedTargets.filter(
    (target) => !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}$/u.test(target),
  );
  const exactEvidenceRequirements = request.contract.evidenceRequirements.length === 1
    && request.contract.evidenceRequirements[0] === "dns_certificate_record";
  const terminalReportDeliverables = new Set<string>(AUTONOMOUS_TERMINAL_REPORT_DELIVERABLE_IDS);
  const unsupportedDeliverables = request.contract.deliverables.filter(
    (deliverableId) => !terminalReportDeliverables.has(deliverableId),
  );
  return [
    unsupportedCriteria.length === 0
      && request.successCriteria.length === 1
      ? {
          id: "contract_outcome_capability",
          label: "Executable success criteria",
          status: "pass",
          journeys: ["autonomous"],
          impact: "The exact DNS result criterion is backed by the mounted verifier and terminal evaluator.",
        }
      : {
          id: "contract_outcome_capability",
          label: "Executable success criteria",
          status: "fail",
          journeys: ["autonomous"],
          impact: "The current Autonomous Safe Recon executor cannot prove one or more custom or template-level success criteria.",
          remediation: `Use the registry-backed criterion: ${AUTONOMOUS_DNS_A_SUCCESS_CRITERION}`,
        },
    nonDomainTargets.length === 0 && request.authorization.allowedTargets.length === 1
      ? {
          id: "contract_target_capability",
          label: "Executable DNS target scope",
          status: "pass",
          journeys: ["autonomous"],
          impact: "The one allowed target is an exact domain name supported by the one-step reviewed DNS binding.",
        }
      : {
          id: "contract_target_capability",
          label: "Executable DNS target scope",
          status: "fail",
          journeys: ["autonomous"],
          impact: "The DNS-only Autonomous executor supports exactly one domain per run and cannot safely reinterpret or silently drop extra targets.",
          remediation: "Supply one exact authorized domain target. Create another run for each additional domain until a reviewed multi-target planner is mounted.",
        },
    exactEvidenceRequirements
      ? {
          id: "contract_exact_evidence_capability",
          label: "Executable evidence requirement",
          status: "pass",
          journeys: ["autonomous"],
          impact: "The exact DNS evidence requirement is produced and verified by the mounted result boundary.",
        }
      : {
          id: "contract_exact_evidence_capability",
          label: "Executable evidence requirement",
          status: "fail",
          journeys: ["autonomous"],
          impact: "The DNS-only Autonomous executor cannot produce one or more selected evidence types.",
          remediation: "Require exactly dns_certificate_record for this bounded DNS run, or mount another reviewed evidence producer.",
        },
    unsupportedDeliverables.length === 0
      ? {
          id: "contract_deliverable_capability",
          label: "Executable deliverables",
          status: "pass",
          journeys: ["autonomous"],
          impact: request.contract.deliverables.length === 0
            ? "No optional report was selected; verified DNS evidence and the terminal evaluation remain available in the mission record."
            : "Every selected deliverable is backed by the atomic canonical terminal report producer.",
        }
      : {
          id: "contract_deliverable_capability",
          label: "Executable deliverables",
          status: "fail",
          journeys: ["autonomous"],
          impact: `The current bounded DNS slice cannot produce: ${unsupportedDeliverables.join(", ")}.`,
          remediation: "Select the canonical machine-readable or Markdown report deliverables, or connect and attest another exact producer before launch.",
        },
  ];
}

function materialObjectiveCoverageReadiness(
  request: AutonomousMissionRequest,
): AutonomousMissionPreflight["readiness"]["checks"][number] {
  const requirements = autonomousMaterialObjectiveRequirements(
    request.objective,
  );
  if (requirements.length === 0) {
    return {
      id: "contract_material_objective_coverage",
      label: "Material objective coverage",
      status: "pass",
      journeys: ["autonomous"],
      impact: "No explicit exploit execution, initial-access, user-access, or root-access outcome was detected outside the signed measurable criteria.",
    };
  }

  const criteria = new Set(
    request.successCriteria.map((criterion) =>
      criterion.trim().normalize("NFKC").replace(/\s+/gu, " ")
        .toLocaleLowerCase("en-US")),
  );
  const allowedActionClasses = new Set(request.contract.allowedActionClasses);
  const missingCriteria = [...new Set(requirements.flatMap(
    ({ successCriteria }) => successCriteria,
  ))].filter((criterion) =>
    !criteria.has(
      criterion.trim().normalize("NFKC").replace(/\s+/gu, " ")
        .toLocaleLowerCase("en-US"),
    ));
  const missingActionClassIds = [...new Set(requirements.flatMap(
    ({ requiredActionClassIds }) => requiredActionClassIds,
  ))].filter((actionClassId) => !allowedActionClasses.has(actionClassId));
  const labels = requirements.map(({ label }) => label);

  if (missingCriteria.length > 0 || missingActionClassIds.length > 0) {
    return {
      id: "contract_material_objective_coverage",
      label: "Material objective coverage",
      status: "fail",
      journeys: ["autonomous"],
      impact: [
        `The authorized objective explicitly requests ${labels.join(", ")}, but the reviewed contract cannot represent every requested outcome.`,
        ...(missingCriteria.length > 0
          ? [`Missing evidence-backed success criteria: ${missingCriteria.join("; ")}.`]
          : []),
        ...(missingActionClassIds.length > 0
          ? [`Missing pre-authorized action classes: ${missingActionClassIds.join(", ")}.`]
          : []),
      ].join(" "),
      remediation: "Resolve the objective through the registry-backed intake so Ti-Scale adds every canonical criterion, then select a reviewed capable contract; otherwise narrow the objective before signing. Reconnaissance alone cannot satisfy an access or exploit objective.",
    };
  }

  return {
    id: "contract_material_objective_coverage",
    label: "Material objective coverage",
    status: "pass",
    journeys: ["autonomous"],
    impact: `Every explicit material outcome (${labels.join(", ")}) is retained as a canonical evidence-backed criterion and has its required action classes in the signed policy.`,
  };
}

function autonomousOutcomeContractReadiness(
  request: AutonomousMissionRequest,
): AutonomousMissionPreflight["readiness"]["checks"][number] {
  const outcome = resolveAutonomousOutcomeProfile({
    explicitProfileId: request.contract.outcomeProfile,
    objective: request.objective,
    successCriteria: request.successCriteria,
  });
  if (outcome.id === "assessment") {
    return {
      id: "contract_autonomous_outcome",
      label: "Autonomous completion promise",
      status: "pass",
      journeys: ["autonomous"],
      impact:
        "This is an Autonomous Assessment. Completion evaluates only the signed assessment criteria and does not claim exploit success, a session, user access, root access, or cleanup.",
    };
  }

  const normalizedCriteria = new Set(
    request.successCriteria.map((criterion) =>
      criterion.trim().normalize("NFKC").replace(/\s+/gu, " ")
        .toLocaleLowerCase("en-US")),
  );
  const allowed = new Set(request.contract.allowedActionClasses);
  const missingCriteria =
    AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_SUCCESS_CRITERIA.filter(
      (criterion) => !normalizedCriteria.has(
        criterion.trim().normalize("NFKC").replace(/\s+/gu, " ")
          .toLocaleLowerCase("en-US"),
      ),
    );
  const missingActionClassIds =
    AUTONOMOUS_HTB_WEB_FULL_PATH_TERMINAL_ACTION_CLASS_IDS.filter(
      (actionClassId) => !allowed.has(actionClassId),
    );
  if (missingCriteria.length > 0 || missingActionClassIds.length > 0) {
    return {
      id: "contract_autonomous_outcome",
      label: "Complete Autonomous Engagement route",
      status: "fail",
      journeys: ["autonomous"],
      impact: [
        "This contract promises a Complete Autonomous Engagement, but its exploit-to-root-and-cleanup route is incomplete.",
        ...(missingCriteria.length > 0
          ? [`Missing terminal proof criteria: ${missingCriteria.join("; ")}.`]
          : []),
        ...(missingActionClassIds.length > 0
          ? [`Missing pre-authorized execution classes: ${missingActionClassIds.join(", ")}.`]
          : []),
        "A deferred exploit, possible CVE, reconnaissance result, or partial session cannot satisfy this promise.",
      ].join(" "),
      remediation:
        "Use the reviewed Complete Autonomous Engagement contract with all six terminal proof criteria and every exploit, session, impact, privilege, and cleanup action class, then repair any runtime-executability blocker reported by preflight.",
    };
  }
  return {
    id: "contract_autonomous_outcome",
    label: "Complete Autonomous Engagement route",
    status: "pass",
    journeys: ["autonomous"],
    impact:
      "All six terminal proof criteria and every required exploit, session, user/root proof, privilege, and cleanup action class are signed. Runtime preflight must separately prove each class is executable before launch.",
  };
}

export class MissionService {
  constructor(
    private readonly missions: MissionRepository,
    private readonly overview: OverviewRepository,
    private readonly readiness: ReadinessService,
    private readonly brainContext: BrainContextService,
    private readonly readRuntimeManifests: () => RuntimeSourceManifests = emptyRuntimeSourceManifests,
    private readonly memoryGraph?: CanonicalMissionMemoryGraph,
    /** Post-commit sink. Implementations must isolate optional Vault failures. */
    private readonly projectMemoryNodes?: (nodeIds: readonly string[]) => void,
    /** Production launch boundary for scoped resolution and immutable pinning. */
    private readonly modelConfigurations?: AutonomousModelConfigurationBoundary,
  ) {}

  async preflightAutonomous(request: AutonomousMissionRequest): Promise<AutonomousMissionPreflight> {
    const contractHash = autonomousContractHash(request);
    const outcome = resolveAutonomousOutcomeProfile({
      explicitProfileId: request.contract.outcomeProfile,
      objective: request.objective,
      successCriteria: request.successCriteria,
    });
    const base = await this.readiness.evaluateJourney("autonomous", { request });
    const context = this.missions.autonomousContextPreview(request);
    const projectedExecution = this.missions.autonomousExecutionPreview(request);
    let execution: AutonomousMissionPreflight["execution"] = {
      ...projectedExecution,
      team: {
        ...projectedExecution.team,
        modelAssignments: [],
      },
    };
    const modelCompatibleCandidateIds = new Set<string>();
    const modelIncompatibilityReasons = new Map<string, string>();
    for (const candidate of projectedExecution.team.candidates) {
      if (!candidate.compatible) continue;
      if (!this.modelConfigurations) {
        modelIncompatibilityReasons.set(
          candidate.id,
          "No live model-assignment validator is available for this specialist.",
        );
        continue;
      }
      try {
        const batch = this.modelConfigurations.resolveAutonomousAssignments({
          specialistAgentIds: [candidate.id],
          overrides: request.contract.agentModelAssignments.filter(
            ({ agentId }) => agentId === candidate.id,
          ),
          requiredActionClassIds: request.contract.allowedActionClasses,
        });
        const receipt = batch.receipts.find(({ agentId }) =>
          agentId === candidate.id);
        if (receipt?.ready === true) {
          modelCompatibleCandidateIds.add(candidate.id);
          continue;
        }
        modelIncompatibilityReasons.set(
          candidate.id,
          receipt?.reasons.join(" ").trim()
            || "No current enforced model configuration can execute every action class required by this contract.",
        );
      } catch (error) {
        modelIncompatibilityReasons.set(
          candidate.id,
          error instanceof ModelConfigurationError
            ? `${error.message}. ${error.remediation}`
            : "The live model catalog could not verify an executable configuration for this specialist.",
        );
      }
    }
    const modelAwareCandidates = projectedExecution.team.candidates.map(
      (candidate) => {
        const modelReason = modelIncompatibilityReasons.get(candidate.id);
        return modelReason
          ? {
              ...candidate,
              compatible: false,
              incompatibilityReasons: [
                ...candidate.incompatibilityReasons,
                modelReason,
              ],
            }
          : candidate;
      },
    );
    const modelAwareCandidateById = new Map(
      modelAwareCandidates.map((candidate) => [candidate.id, candidate]),
    );
    const selectedAgentIds = projectedExecution.team.selectedAgentIds;
    const invalidSelectedAgentIds = selectedAgentIds.filter((agentId) =>
      modelAwareCandidateById.get(agentId)?.compatible !== true);
    execution = {
      ...execution,
      team: {
        ...execution.team,
        candidates: modelAwareCandidates,
        invalidSelectedAgentIds,
        recommendedAgentIds: projectedExecution.team.recommendedAgentIds.filter(
          (agentId) => modelCompatibleCandidateIds.has(agentId),
        ),
        effectiveAgentIds: selectedAgentIds.filter(
          (agentId) => !invalidSelectedAgentIds.includes(agentId),
        ),
      },
    };
    const checks = [...base.checks];
    const scopedMemoryRequired = request.contract.memoryScopes.length > 0
      || request.contract.contextNodeIds.length > 0;
    const memoryAvailability = scopedMemoryRequired
      ? this.brainContext.readAvailability("intake", "autonomous")
      : { available: true as const };
    checks.push(!memoryAvailability.available
      ? {
          id: "contract_memory_runtime",
          label: "Required Second Brain runtime",
          status: "fail",
          journeys: ["autonomous"],
          impact: "The signed contract requires scoped Second Brain retrieval, but the canonical memory runtime or Autonomous memory control is unavailable.",
          remediation: "Restore the canonical Second Brain dependency and enable Autonomous memory use, or remove every memory scope in a newly reviewed contract before launch.",
        }
      : {
          id: "contract_memory_runtime",
          label: "Required Second Brain runtime",
          status: "pass",
          journeys: ["autonomous"],
          impact: scopedMemoryRequired
            ? "The canonical Second Brain dependency and Autonomous memory control are available for the signed scoped retrieval policy."
            : "This contract requests no reusable memory scope; lifecycle hooks will persist explicit empty Context Packs without claiming remembered influence.",
        });
    const attackMemoryRequired = request.contract.memoryScopes.some((scope) =>
      scope === "confirmed_attack_knowledge"
      || scope === "verified_attack_knowledge");
    const activeVaultAvailability = attackMemoryRequired
      ? this.brainContext.readActiveVaultAvailability(request.contract.contextNodeIds)
      : { available: true as const };
    checks.push(!activeVaultAvailability.available
      ? {
          id: "contract_attack_memory_vault",
          label: "Active Obsidian attack-knowledge Vault",
          status: "fail",
          journeys: ["autonomous"],
          impact: activeVaultAvailability.explanation
            ?? "The signed attack-knowledge scope has no usable active Obsidian Vault projection.",
          remediation: "Connect the Ti-Scale Attack Knowledge Vault, complete its round-trip health check, resolve conflicts, synchronize exact selected nodes at their current version, and rerun preflight.",
        }
      : {
          id: "contract_attack_memory_vault",
          label: "Active Obsidian attack-knowledge Vault",
          status: "pass",
          journeys: ["autonomous"],
          impact: attackMemoryRequired
            ? "The user-owned active Obsidian Vault is connected and health-verified; exact selected memories are synchronized at their current canonical versions."
            : "This contract does not request reusable attack-knowledge memory, so an active Vault is not required by this check.",
        });
    checks.push(request.contract.allowedActionClasses.length > 0
      ? {
          id: "contract_action_boundary",
          label: "Executable action boundary",
          status: "pass",
          journeys: ["autonomous"],
          impact: `${request.contract.allowedActionClasses.length} exact action class${request.contract.allowedActionClasses.length === 1 ? " is" : "es are"} permitted by this reviewed contract.`,
        }
      : {
          id: "contract_action_boundary",
          label: "Executable action boundary",
          status: "fail",
          journeys: ["autonomous"],
          impact: "Recommended defaults could not find a supported, locally enforced action class, so Autonomous has no executable boundary.",
          remediation: "Connect and validate a compatible specialist/tool path, or explicitly choose a supported action class, then rerun preflight.",
        });
    checks.push(requiredEvidenceReadiness(request, this.readRuntimeManifests));
    checks.push(autonomousOutcomeContractReadiness(request));
    checks.push(materialObjectiveCoverageReadiness(request));
    checks.push(...exactExploitValidationContractReadiness(request));
    checks.push(...exactDnsOutcomeReadiness(request));
    checks.push(context.invalidSelectedNodeIds.length > 0
      ? {
          id: "contract_memory_selection",
          label: "Selected Second Brain context",
          status: "fail",
          journeys: ["autonomous"],
          impact: `${context.invalidSelectedNodeIds.length} selected memory node${context.invalidSelectedNodeIds.length === 1 ? " is" : "s are"} no longer eligible for this mission scope.`,
          remediation: "Remove stale, unconfirmed, restricted, expired, or cross-engagement nodes and review the contract again.",
        }
      : {
          id: "contract_memory_selection",
          label: "Selected Second Brain context",
          status: "pass",
          journeys: ["autonomous"],
          impact: context.selectedNodeIds.length > 0
            ? `${context.selectedNodeIds.length} exact confirmed or verified memory node${context.selectedNodeIds.length === 1 ? " is" : "s are"} pinned. The core agent will also retrieve the smallest relevant confirmed or verified context permitted by the ${request.contract.memoryScopes.length} signed memory scope${request.contract.memoryScopes.length === 1 ? "" : "s"}.`
            : request.contract.memoryScopes.length > 0
              ? `No exact memory nodes are pinned. The core agent will retrieve the smallest relevant confirmed or verified context permitted by the ${request.contract.memoryScopes.length} signed memory scope${request.contract.memoryScopes.length === 1 ? "" : "s"}.`
              : "Second Brain use is disabled for this contract, so the run will use an explicit empty Context Pack.",
        });
    if (request.contractReview && (
      request.contractReview.version !== 1 || request.contractReview.hash !== contractHash
    )) {
      checks.push({
        id: "contract_review_integrity",
        label: "Contract review integrity",
        status: "fail",
        journeys: ["autonomous"],
        impact: "The submitted review digest does not match the current contract contents.",
        remediation: "Run preflight again and deliberately review the newly issued version and digest.",
      });
    } else {
      checks.push({
        id: "contract_review_integrity",
        label: "Contract review integrity",
        status: "pass",
        journeys: ["autonomous"],
        impact: request.contractReview
          ? "The operator-reviewed version and SHA-256 match the exact contract that will be persisted."
          : "The server issued a versioned SHA-256 for deliberate review before launch.",
      });
    }
    const compatibleProviders = execution.providers.filter((provider) => provider.compatible);
    checks.push(compatibleProviders.length > 0
      ? {
          id: "contract_provider_inventory",
          label: "Inspected enforcing provider paths",
          status: "pass",
          journeys: ["autonomous"],
          impact: `${compatibleProviders.length} projected authenticated provider path${compatibleProviders.length === 1 ? " is" : "s are"} compatible with the Autonomous boundary; live readiness is also rechecked at launch.`,
        }
      : {
          id: "contract_provider_inventory",
          label: "Inspected enforcing provider paths",
          status: "fail",
          journeys: ["autonomous"],
          impact: "The canonical runtime projection contains no authenticated provider path compatible with the Autonomous boundary.",
          remediation: "Restore an enforcing provider, wait for runtime projection health to update, and rerun preflight.",
        });
    const selectedCount = execution.team.selectedAgentIds.length;
    const invalidCount = execution.team.invalidSelectedAgentIds.length;
    checks.push(selectedCount === 0
      ? {
          id: "contract_specialist_selection",
          label: "Signed specialist pool",
          status: "fail",
          journeys: ["autonomous"],
          impact: "No exact specialist is selected, so the planner would not have a reviewed assignment boundary.",
          remediation: "Select at least one compatible specialist from the inspected fleet.",
        }
      : invalidCount > 0 || execution.team.effectiveAgentIds.length === 0
        ? {
            id: "contract_specialist_selection",
            label: "Signed specialist pool",
            status: "fail",
            journeys: ["autonomous"],
            impact: `${invalidCount} selected specialist${invalidCount === 1 ? " is" : "s are"} unavailable, unknown, or incompatible with this contract.`,
            remediation: "Remove incompatible specialists and select at least one candidate marked compatible.",
          }
        : {
            id: "contract_specialist_selection",
            label: "Signed specialist pool",
            status: "pass",
            journeys: ["autonomous"],
            impact: `${execution.team.effectiveAgentIds.length} exact compatible specialist${execution.team.effectiveAgentIds.length === 1 ? " is" : "s are"} bound into the contract and planner inventory.`,
          });
    if (this.modelConfigurations) {
      let modelFailure: string | null = null;
      try {
        const batch = this.modelConfigurations.validateAutonomousAssignments({
          assignments: request.contract.agentModelAssignments,
          specialistAgentIds: request.contract.specialistAgentIds,
          requiredActionClassIds: request.contract.allowedActionClasses,
        });
        execution = {
          ...execution,
          team: {
            ...execution.team,
            modelAssignments: batch.receipts,
          },
        };
      } catch (error) {
        modelFailure = error instanceof Error
          ? error.message
          : "The exact signed model assignment set could not be validated.";
      }
      const modelBlockers = execution.team.modelAssignments.filter(
        ({ ready }) => !ready,
      );
      checks.push(!modelFailure && modelBlockers.length === 0
        ? {
            id: "contract_agent_model_assignments",
            label: "Pinned specialist model configurations",
            status: "pass",
            journeys: ["autonomous"],
            impact: `${request.contract.specialistAgentIds.length} exact signed specialist model configuration${request.contract.specialistAgentIds.length === 1 ? " is" : "s are"} present in current live-attested provider data and will be pinned unchanged before planning starts.`,
          }
        : {
            id: "contract_agent_model_assignments",
            label: "Pinned specialist model configurations",
            status: "fail",
            journeys: ["autonomous"],
            impact: modelFailure
              ?? `Model configuration is unavailable for: ${modelBlockers.map(({ agentId, reasons }) => `${agentId} (${reasons.join(" ")})`).join(", ")}.`,
            remediation: "Refresh the live catalog, choose an enforced compatible primary and fallback for every specialist, and deliberately review the newly issued contract digest.",
          });
    } else {
      checks.push({
        id: "contract_agent_model_assignments",
        label: "Pinned specialist model configurations",
        status: "fail",
        journeys: ["autonomous"],
        impact: "The exact model-assignment validator is unavailable, so Ti-Scale cannot prove or pin the signed specialist configurations.",
        remediation: "Restore the canonical model-configuration service and rerun preflight. Do not launch from unvalidated defaults.",
      });
    }
    const planningSelection = resolveAutonomousPlanningSelection(
      request.contract.planningSelection,
    );
    if (planningSelection.route === "local_deterministic") {
      checks.push({
        id: "contract_planning_selection",
        label: "Signed planning route",
        status: "pass",
        journeys: ["autonomous"],
        impact:
          "Plan construction is pinned to Ti-Scale's local deterministic planner. No mission context is disclosed to a provider and this selection grants no execution authority.",
      });
    } else if (
      !this.modelConfigurations
      || !this.modelConfigurations.validateAutonomousPlanningSelection
    ) {
      checks.push({
        id: "contract_planning_selection",
        label: "Signed planning route",
        status: "fail",
        journeys: ["autonomous"],
        impact:
          "The signed provider-advisory planning selection cannot be revalidated because the planning model validator is unavailable.",
        remediation:
          "Restore the canonical model-configuration service, or select the local deterministic planner and review a new contract digest.",
      });
    } else {
      let planningFailure: string | null = null;
      let planningReady = false;
      try {
        const receipt =
          this.modelConfigurations.validateAutonomousPlanningSelection(
            planningSelection,
          );
        planningReady = receipt?.ready === true;
        if (receipt && !receipt.ready) {
          planningFailure = receipt.reasons.join(" ").trim();
        }
      } catch (error) {
        planningFailure = error instanceof ModelConfigurationError
          ? `${error.message}. ${error.remediation}`
          : error instanceof Error
            ? error.message
            : "The signed planning configuration could not be validated.";
      }
      checks.push(planningReady
        ? {
            id: "contract_planning_selection",
            label: "Signed planning route",
            status: "pass",
            journeys: ["autonomous"],
            impact:
              `Plan construction is pinned to advisor-only agent ${planningSelection.agentId} with the signed ${planningSelection.disclosureClass.replaceAll("_", " ")} disclosure boundary and no execution authority.`,
          }
        : {
            id: "contract_planning_selection",
            label: "Signed planning route",
            status: "fail",
            journeys: ["autonomous"],
            impact: planningFailure
              || "The exact signed provider-advisory planning configuration is not ready.",
            remediation:
              "Choose a current authenticated, healthy advisor-only model with structured output and the exact disclosure class, then review a new contract digest.",
          });
    }
    return {
      schemaVersion: "2.4",
      outcome,
      contract: { version: 1, hash: contractHash },
      readiness: readinessSummary(checks),
      context,
      execution,
      policySummary: {
        provider: `Automatic selection across ${compatibleProviders.length} inspected authenticated enforcing path${compatibleProviders.length === 1 ? "" : "s"}.`,
        tools: `${execution.team.candidates.flatMap(({ runnableTools }) => runnableTools).filter((tool, index, values) => values.indexOf(tool) === index).length} inspected runnable reviewed execution binding${execution.tools.length === 1 ? "" : "s"}; planner assignments are restricted to ${execution.team.effectiveAgentIds.length} signed specialist${execution.team.effectiveAgentIds.length === 1 ? "" : "s"}.`,
        notifications: "In-product semantic events only; no external channel is implied.",
        reporting: "Scope-checked Ti-Scale JSON completion bundle with integrity digest.",
        retention: "Local private data plane with operator-managed retention; no unenforced automatic expiry is promised.",
        storage: `${request.contract.evidenceStorageBudgetBytes} evidence bytes and ${request.contract.artifactStorageBudgetBytes} artifact bytes.`,
      },
    };
  }

  async create(
    request: MissionCreateRequest,
    idempotencyKey: string,
    actorId: string,
  ): Promise<CreatedMission> {
    const requestHash = hashCanonical(request);
    const replay = this.missions.getIdempotentCreate(idempotencyKey, requestHash);
    if (replay) {
      if (this.memoryGraph) {
        try {
          const graph = this.memoryGraph.ensureRun(replay.run.id);
          this.projectCanonicalNodes(graph.nodeIds);
        } catch {
          // The canonical mission already exists. Deferred reconciliation is
          // safer than returning an error that could cause a duplicate launch.
          try {
            this.missions.recordCanonicalGraphDeferred({
              missionId: replay.mission.id,
              runId: replay.run.id,
            });
          } catch {
            // Preserve the idempotent canonical response even if the optional
            // repair audit store is independently unavailable.
          }
        }
      }
      return replay;
    }

    if (request.journey === "autonomous") {
      const expectedContractHash = autonomousContractHash(request);
      if (
        !request.contractReview
        || request.contractReview.version !== 1
        || request.contractReview.hash !== expectedContractHash
      ) {
        throw new MissionApiError(409, "autonomous_contract_confirmation_required", "Autonomous contract confirmation is required", {
          humanMessage: "Review and confirm the exact server-issued Autonomous contract before launch.",
          category: "policy_denied",
          remediation: "Run Autonomous preflight, review its version and SHA-256, then submit that exact contractReview with the launch request.",
        });
      }
      const readiness = (await this.preflightAutonomous(request)).readiness;
      const blockers = readiness.checks.filter((check) => check.status === "fail");
      if (blockers.length > 0) {
        throw new AutonomousReadinessError({
          status: readiness.status,
          score: readiness.score,
          checks: blockers.map((check) => ({
            id: check.id,
            label: check.label,
            status: check.status,
            impact: check.impact,
            journeys: [...check.journeys],
            remediation: check.remediation ?? null,
          })),
        });
      }
    }

    try {
      let canonicalNodeIds: readonly string[] = [];
      const created = this.missions.create({
        request,
        requestHash,
        idempotencyKey,
        actorId,
        resolveIntakeContext: ({ missionId, memoryPolicy }): MissionIntakeContextBinding => {
          const canonical = this.memoryGraph?.ensureMission(missionId);
          const lifecyclePreferenceNodeIds = request.journey === "autonomous"
            ? this.brainContext.resolveLifecyclePreferenceNodeIds({
                missionId,
                operatorId: actorId,
                journey: request.journey,
                hook: "intake",
                preferenceKeys: [
                  "autonomy.default_posture",
                  "communication.technical_readability",
                  "communication.evidence_first",
                ],
              })
            : undefined;
          const result = retrieveMissionBrainContext({
            brainContext: this.brainContext,
            hook: "intake",
            journey: request.journey,
            missionId,
            actorId,
            actorType: "operator",
            query: missionIntakeQuery(request),
            queryRedacted: redactedMissionIntakeQuery(request),
            memoryPolicy,
            ...(canonical ? { canonicalContextNodeIds: canonical.nodeIds } : {}),
            ...(lifecyclePreferenceNodeIds
              ? { lifecyclePreferenceNodeIds }
              : {}),
          });
          const preferenceApplication = request.journey === "autonomous"
            ? applyAutonomousIntakePreferenceDefaults({
                context: result,
                profiles: this.brainContext.confirmedPreferenceProfiles(result, actorId),
              })
            : undefined;
          if (preferenceApplication) {
            this.brainContext.recordContextDispositions(
              result,
              preferenceApplication.dispositions,
            );
          } else {
            this.brainContext.recordUnusedContext(
              result,
              "Mission intake defaults remained deterministic; this Context Pack was retrieved for scope-safe continuity and did not alter inferred fields.",
            );
          }
          return {
            hook: "intake",
            contextPackId: result.contextPack.id,
            auditRecordId: result.auditRecordId,
            status: result.status,
            retrievedCount: result.items.length,
            memoryInfluencedDefaults:
              preferenceApplication?.memoryInfluencedDefaults ?? false,
            ...(preferenceApplication?.safeOptionalDefaults
              ? { safeOptionalDefaults: preferenceApplication.safeOptionalDefaults }
              : {}),
            ...(preferenceApplication?.influenceExplanation
              ? { influenceExplanation: preferenceApplication.influenceExplanation }
              : {}),
            ...(result.degradation ? { degradation: result.degradation } : {}),
          };
        },
        ...(this.memoryGraph ? {
          materializeCanonicalGraph: ({ runId }) => {
            const graph = this.memoryGraph!.ensureRun(runId);
            canonicalNodeIds = graph.nodeIds;
            return graph.nodeIds;
          },
        } : {}),
        ...(this.modelConfigurations ? {
          pinModelAssignments: ({
            missionId,
            runId,
            specialistAgentIds,
            planningSelection,
            agentModelAssignments,
            allowedActionClasses,
          }) => {
            try {
              const pinned = [
                ...this.modelConfigurations!.pinExactAutonomousAssignments({
                  assignments: agentModelAssignments,
                  specialistAgentIds,
                  requiredActionClassIds: allowedActionClasses,
                  missionId,
                  runId,
                  resolutionReason:
                    "Pinned transactionally before mission planning from the exact operator-reviewed Autonomous mission contract",
                }),
              ];
              if (planningSelection.route === "provider_advisory") {
                const pinPlanning =
                  this.modelConfigurations!.pinExactAutonomousPlanningSelection;
                if (!pinPlanning) {
                  throw new MissionApiError(
                    503,
                    "mission_planning_configuration_service_unavailable",
                    "Provider-advisory planning pin service is unavailable",
                    {
                      humanMessage:
                        "Mission launch stopped before planning because Ti-Scale could not pin the signed advisor-only planning configuration.",
                      category: "dependency_missing",
                      remediation:
                        "Restore the canonical planning configuration service, or select local deterministic planning and review a new contract digest.",
                    },
                  );
                }
                const planningPin = pinPlanning.call(
                  this.modelConfigurations,
                  {
                    selection: planningSelection,
                    missionId,
                    runId,
                    resolutionReason:
                      "Pinned transactionally before mission planning from the exact operator-reviewed provider-advisory planning selection",
                  },
                );
                if (planningPin) pinned.push(planningPin);
              }
              const pinSpecialistAdvisors =
                this.modelConfigurations!
                  .pinSelectedSpecialistAdvisoryAssignments;
              if (pinSpecialistAdvisors) {
                pinned.push(...pinSpecialistAdvisors.call(
                  this.modelConfigurations,
                  { specialistAgentIds, missionId, runId },
                ));
              }
              return pinned.map(({ id }) => id);
            } catch (error) {
              if (!(error instanceof ModelConfigurationError)) throw error;
              throw new MissionApiError(
                error.status === 404 ? 409 : error.status,
                "mission_model_configuration_unavailable",
                error.message,
                {
                  humanMessage:
                    "Mission launch stopped before planning because a selected specialist has no current usable model configuration.",
                  category: error.category,
                  remediation:
                    "Refresh the live model catalog, configure every selected specialist, rerun preflight, and launch the unchanged reviewed contract.",
                },
              );
            }
          },
        } : {}),
      });
      this.projectCanonicalNodes(canonicalNodeIds);
      return created;
    } catch (error) {
      if (!(error instanceof BrainContextHookError) || error.hook !== "intake") throw error;
      let auditRecordId: string | undefined;
      try {
        auditRecordId = this.missions.recordIntakeContextBlocked({
          requestHash,
          journey: request.journey,
          actorId,
          code: error.code,
          explanation: error.message,
        });
      } catch {
        // Preserve the original fail-closed error when the database cannot
        // retain even the privacy-safe, unscoped attempt receipt.
      }
      throw new BrainContextHookError(
        error.code,
        error.hook,
        error.message,
        auditRecordId,
        { cause: error },
      );
    }
  }

  private projectCanonicalNodes(nodeIds: readonly string[]): void {
    try {
      this.projectMemoryNodes?.(nodeIds);
    } catch {
      // Mission creation is already committed. Obsidian is an optional
      // projection and may never turn a valid canonical mutation into an
      // ambiguous client failure or roll it back.
    }
  }

  async getOverview(): Promise<OverviewSnapshot> {
    const readiness = await this.readiness.evaluate();
    return { ...this.overview.readData(), readiness };
  }

  list(options: ListMissionsOptions = {}): MissionListPage {
    return this.missions.list(options);
  }
}
