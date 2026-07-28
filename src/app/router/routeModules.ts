import type { ElementType } from "react";

interface ReactRouteThenable<T> extends Promise<T> {
  status?: "pending" | "fulfilled" | "rejected";
  value?: T;
  reason?: unknown;
}

export interface CachedRouteModuleLoader<T = unknown> {
  (): Promise<T>;
  peek: () => T | undefined;
}

/**
 * Keep one instrumented promise per route module. Navigation resolves it while
 * the current route remains visible; the stable route wrapper can then consume
 * the fulfilled thenable synchronously at the mechanical commit instead of
 * flashing its Suspense fallback for one frame.
 */
function cachedRouteLoader<T>(load: () => Promise<T>): CachedRouteModuleLoader<T> {
  let cached: ReactRouteThenable<T> | undefined;
  let loaded: T | undefined;
  const loader = () => {
    if (cached) return cached;
    cached = load() as ReactRouteThenable<T>;
    cached.status = "pending";
    void cached.then(
      (value) => {
        if (cached?.status === "pending") {
          cached.status = "fulfilled";
          cached.value = value;
          loaded = value;
        }
      },
      (reason: unknown) => {
        if (cached?.status === "pending") {
          cached.status = "rejected";
          cached.reason = reason;
        }
      },
    );
    return cached;
  };
  loader.peek = () => loaded;
  return loader;
}

export const loadMissionPortfolioPage = cachedRouteLoader(() => import("../../features/missions/MissionPortfolioPage"));
export const loadJourneySelectionPage = cachedRouteLoader(() => import("../../features/missions/JourneySelectionPage"));
export const loadAutonomousContractPage = cachedRouteLoader(() => import("../../features/missions/AutonomousContractPage"));
export const loadGuidedMissionCreatePage = cachedRouteLoader(() => import("../../features/missions/GuidedMissionCreatePage"));
export const loadBrainHomePage = cachedRouteLoader(() => import("../../features/brain/BrainHomePage"));
export const loadBrainGraphPage = cachedRouteLoader(() => import("../../features/brain/BrainGraphPage"));
export const loadOperatorPreferencesPage = cachedRouteLoader(() => import("../../features/brain/OperatorPreferencesPage"));
export const loadBrainInboxPage = cachedRouteLoader(() => import("../../features/brain/BrainInboxPage"));
export const loadBrainNodePage = cachedRouteLoader(() => import("../../features/brain/BrainNodePage"));
export const loadBrainControlPage = cachedRouteLoader(() => import("../../features/brain/BrainControlPage"));
export const loadBrainVaultPage = cachedRouteLoader(() => import("../../features/brain/BrainVaultPage"));
export const loadAgentsPage = cachedRouteLoader(() => import("../../features/agents/AgentsPage"));
export const loadIntelligencePage = cachedRouteLoader(() => import("../../features/intelligence/IntelligencePage"));
export const loadObservabilityPage = cachedRouteLoader(() => import("../../features/observability/ObservabilityPage"));
export const loadLearningPage = cachedRouteLoader(() => import("../../features/learning/LearningPage"));
export const loadReportsPage = cachedRouteLoader(() => import("../../features/reports/ReportsPage"));
export const loadSystemPage = cachedRouteLoader(() => import("../../features/system/SystemPage"));
export const loadDecisionsPage = cachedRouteLoader(() => import("../../features/decisions/DecisionsPage"));
export const loadLiveOperationsPage = cachedRouteLoader(() => import("../../features/live-operations/LiveOperationsPage"));
export const loadGuidedWorkspacePage = cachedRouteLoader(() => import("../../features/guided/GuidedWorkspacePage"));
export const loadRunWorkspacePage = cachedRouteLoader(() => import("../../features/runs/RunWorkspacePage"));
export const loadUserManualPage = cachedRouteLoader(() => import("../../features/manual/UserManualPage"));
export const loadMotionLabPage = cachedRouteLoader(() => import("../../features/motion-lab/MotionLabPage"));
export const loadParticleCoreReviewPage = cachedRouteLoader(() => import("../../features/motion-lab/ParticleCoreReviewPage"));
export const loadParticleModuleTransitionPage = cachedRouteLoader(() => import("../../features/motion-lab/ParticleModuleTransitionPage"));
export const loadModelCandidateReviewPage = cachedRouteLoader(() => import("../../features/motion-lab/ModelCandidateReviewPage"));

type RouteModuleLoader = CachedRouteModuleLoader<unknown>;

function routeModuleLoader(pathname: string): RouteModuleLoader | undefined {
  if (pathname === "/missions") return loadMissionPortfolioPage;
  if (pathname === "/missions/new") return loadJourneySelectionPage;
  if (pathname === "/missions/new/autonomous") return loadAutonomousContractPage;
  if (pathname === "/missions/new/guided") return loadGuidedMissionCreatePage;
  if (pathname.startsWith("/missions/")) return loadRunWorkspacePage;
  if (pathname === "/guided" || pathname.startsWith("/guided/")) return loadGuidedWorkspacePage;
  if (pathname === "/live" || pathname.startsWith("/live/")) return loadLiveOperationsPage;
  if (pathname === "/decisions" || pathname === "/approvals") return loadDecisionsPage;
  if (pathname === "/intelligence" || pathname.startsWith("/intelligence/")) return loadIntelligencePage;
  if (pathname === "/agents" || pathname.startsWith("/agents/")) return loadAgentsPage;
  if (pathname === "/brain") return loadBrainHomePage;
  if (pathname === "/brain/graph") return loadBrainGraphPage;
  if (pathname === "/brain/preferences") return loadOperatorPreferencesPage;
  if (pathname === "/brain/inbox") return loadBrainInboxPage;
  if (pathname === "/brain/control") return loadBrainControlPage;
  if (pathname === "/brain/vault") return loadBrainVaultPage;
  if (pathname.startsWith("/brain/nodes/")) return loadBrainNodePage;
  if (pathname === "/learning" || pathname.startsWith("/learning/") || pathname === "/research") return loadLearningPage;
  if (pathname === "/observability") return loadObservabilityPage;
  if (pathname === "/reports" || pathname.startsWith("/reports/")) return loadReportsPage;
  if (pathname === "/system" || pathname.startsWith("/system/")) return loadSystemPage;
  if (pathname === "/manual") return loadUserManualPage;
  if (pathname === "/motion-lab/assembly") return loadParticleCoreReviewPage;
  if (pathname === "/motion-lab/particle-core") return loadParticleCoreReviewPage;
  if (pathname === "/motion-lab/particle-module-transition") return loadParticleModuleTransitionPage;
  if (pathname === "/motion-lab/candidates") return loadModelCandidateReviewPage;
  if (pathname === "/motion-lab/webgl") return loadParticleCoreReviewPage;
  if (pathname === "/motion-lab") return loadMotionLabPage;
  return undefined;
}

/** Load the selected route while the current route remains stable on screen. */
export function preloadRouteModule(pathname: string): Promise<unknown> {
  return routeModuleLoader(pathname)?.() ?? Promise.resolve(undefined);
}

/** Return the already-resolved page component for a mechanical commit. */
export function getPreloadedRouteComponent(pathname: string): ElementType | undefined {
  const loaded = routeModuleLoader(pathname)?.peek();
  if (!loaded || typeof loaded !== "object" || !("default" in loaded)) return undefined;
  const candidate = (loaded as { default?: unknown }).default;
  return typeof candidate === "function" ? candidate as ElementType : undefined;
}
