import { createElement, Suspense, type ElementType, type ReactNode, use, useEffect } from "react";
import { ButtonLink, LoadingPanel, PageHeader } from "../../design-system/components/Primitives";
import OverviewPage from "../../features/overview/OverviewPage";
import { matchPath, useNavigation } from "./navigation";
import {
  loadAgentsPage,
  loadAutonomousContractPage,
  loadBrainControlPage,
  loadBrainGraphPage,
  loadBrainHomePage,
  loadBrainInboxPage,
  loadBrainNodePage,
  loadOperatorPreferencesPage,
  loadBrainVaultPage,
  loadDecisionsPage,
  loadGuidedMissionCreatePage,
  loadGuidedWorkspacePage,
  loadIntelligencePage,
  loadJourneySelectionPage,
  loadLearningPage,
  loadLiveOperationsPage,
  loadMissionPortfolioPage,
  loadModelCandidateReviewPage,
  loadMotionLabPage,
  loadParticleCoreReviewPage,
  loadParticleModuleTransitionPage,
  loadObservabilityPage,
  loadReportsPage,
  loadRunWorkspacePage,
  loadSystemPage,
  loadUserManualPage,
  type CachedRouteModuleLoader,
} from "./routeModules";

interface RouteModule {
  readonly default: ElementType;
}

/**
 * Keep one React component identity per route while consuming the cached
 * import directly. React.lazy initializes its own payload only on first
 * render, so even an already-fulfilled import can show Suspense for one
 * microtask during a prepared mechanical commit. React 19 `use` recognizes
 * the loader's fulfilled thenable synchronously and still suspends correctly
 * on a direct document load where the module is genuinely pending.
 */
function cachedRouteComponent(loader: CachedRouteModuleLoader<RouteModule>): ElementType {
  return function CachedRouteComponent(props: Record<string, unknown>) {
    const Component = use(loader()).default;
    return createElement(Component, props);
  };
}

const MissionPortfolioPage = cachedRouteComponent(loadMissionPortfolioPage);
const JourneySelectionPage = cachedRouteComponent(loadJourneySelectionPage);
const AutonomousContractPage = cachedRouteComponent(loadAutonomousContractPage);
const GuidedMissionCreatePage = cachedRouteComponent(loadGuidedMissionCreatePage);
const BrainHomePage = cachedRouteComponent(loadBrainHomePage);
const BrainGraphPage = cachedRouteComponent(loadBrainGraphPage);
const OperatorPreferencesPage = cachedRouteComponent(loadOperatorPreferencesPage);
const BrainInboxPage = cachedRouteComponent(loadBrainInboxPage);
const BrainNodePage = cachedRouteComponent(loadBrainNodePage);
const BrainControlPage = cachedRouteComponent(loadBrainControlPage);
const BrainVaultPage = cachedRouteComponent(loadBrainVaultPage);
const AgentsPage = cachedRouteComponent(loadAgentsPage);
const IntelligencePage = cachedRouteComponent(loadIntelligencePage);
const ObservabilityPage = cachedRouteComponent(loadObservabilityPage);
const LearningPage = cachedRouteComponent(loadLearningPage);
const ReportsPage = cachedRouteComponent(loadReportsPage);
const SystemPage = cachedRouteComponent(loadSystemPage);
const DecisionsPage = cachedRouteComponent(loadDecisionsPage);
const LiveOperationsPage = cachedRouteComponent(loadLiveOperationsPage);
const GuidedWorkspacePage = cachedRouteComponent(loadGuidedWorkspacePage);
const RunWorkspacePage = cachedRouteComponent(loadRunWorkspacePage);
const UserManualPage = cachedRouteComponent(loadUserManualPage);
const MotionLabPage = cachedRouteComponent(loadMotionLabPage);
const ParticleCoreReviewPage = cachedRouteComponent(loadParticleCoreReviewPage);
const ParticleModuleTransitionPage = cachedRouteComponent(loadParticleModuleTransitionPage);
const ModelCandidateReviewPage = cachedRouteComponent(loadModelCandidateReviewPage);

function Redirect({ to }: { to: string }) {
  const { navigate } = useNavigation();
  useEffect(() => navigate(to, { replace: true }), [navigate, to]);
  return <div className="os-page"><LoadingPanel label="Opening Ti-Scale surface" /></div>;
}

function LoadingRoute() {
  return <div className="os-page"><LoadingPanel label="Loading Ti-Scale surface" /></div>;
}

export function RouteView() {
  const { pathname } = useNavigation();
  const renderRoute = (fallback: ElementType, props?: Record<string, unknown>): ReactNode => (
    // Keep the same cached wrapper identity after its module resolves. This
    // prevents query-string updates from remounting the route and discarding
    // focus or application-owned control state.
    createElement(fallback, props)
  );
  let route: ReactNode;
  if (pathname === "/") route = <OverviewPage />;
  else if (pathname === "/missions") route = renderRoute(MissionPortfolioPage);
  else if (pathname === "/missions/new") route = renderRoute(JourneySelectionPage);
  else if (pathname === "/missions/new/autonomous") route = renderRoute(AutonomousContractPage);
  else if (pathname === "/missions/new/guided") route = renderRoute(GuidedMissionCreatePage);
  else if (matchPath("/missions/:missionId/runs/:runId", pathname)) { const params = matchPath("/missions/:missionId/runs/:runId", pathname)!; route = renderRoute(RunWorkspacePage, { missionId: params.missionId, runId: params.runId }); }
  else if (matchPath("/missions/:missionId", pathname)) route = renderRoute(RunWorkspacePage, { missionId: matchPath("/missions/:missionId", pathname)!.missionId });
  else if (matchPath("/guided/:missionId", pathname)) route = renderRoute(GuidedWorkspacePage, { missionId: matchPath("/guided/:missionId", pathname)!.missionId });
  else if (pathname === "/guided") route = renderRoute(GuidedWorkspacePage);
  else if (matchPath("/live/:runId", pathname)) route = renderRoute(LiveOperationsPage, { runId: matchPath("/live/:runId", pathname)!.runId });
  else if (pathname === "/live") route = renderRoute(LiveOperationsPage);
  else if (pathname === "/decisions") route = renderRoute(DecisionsPage);
  else if (pathname === "/approvals") route = <Redirect to="/decisions" />;
  else if (pathname === "/intelligence") route = <Redirect to="/intelligence/evidence" />;
  else if (matchPath("/intelligence/evidence/:id", pathname)) route = renderRoute(IntelligencePage, { view: "evidence", selectedId: matchPath("/intelligence/evidence/:id", pathname)!.id });
  else if (matchPath("/intelligence/findings/:id", pathname)) route = renderRoute(IntelligencePage, { view: "findings", selectedId: matchPath("/intelligence/findings/:id", pathname)!.id });
  else if (matchPath("/intelligence/artifacts/:id", pathname)) route = renderRoute(IntelligencePage, { view: "artifacts", selectedId: matchPath("/intelligence/artifacts/:id", pathname)!.id });
  else if (pathname === "/intelligence/evidence") route = renderRoute(IntelligencePage, { view: "evidence" });
  else if (pathname === "/intelligence/findings") route = renderRoute(IntelligencePage, { view: "findings" });
  else if (pathname === "/intelligence/artifacts") route = renderRoute(IntelligencePage, { view: "artifacts" });
  else if (matchPath("/agents/:agentId", pathname)) route = renderRoute(AgentsPage, { agentId: matchPath("/agents/:agentId", pathname)!.agentId });
  else if (pathname === "/agents") route = renderRoute(AgentsPage);
  else if (pathname === "/brain") route = renderRoute(BrainHomePage);
  else if (pathname === "/brain/graph") route = renderRoute(BrainGraphPage);
  else if (pathname === "/brain/preferences") route = renderRoute(OperatorPreferencesPage);
  else if (pathname === "/brain/inbox") route = renderRoute(BrainInboxPage);
  else if (pathname === "/brain/control") route = renderRoute(BrainControlPage);
  else if (pathname === "/brain/vault") route = renderRoute(BrainVaultPage);
  else if (matchPath("/brain/nodes/:memoryNodeId", pathname)) route = renderRoute(BrainNodePage, { nodeId: matchPath("/brain/nodes/:memoryNodeId", pathname)!.memoryNodeId });
  else if (matchPath("/learning/lessons/:lessonId", pathname)) route = renderRoute(LearningPage, { selectedLessonId: matchPath("/learning/lessons/:lessonId", pathname)!.lessonId });
  else if (pathname === "/research") route = <Redirect to="/learning?view=research" />;
  else if (pathname === "/learning") route = renderRoute(LearningPage);
  else if (pathname === "/observability") route = renderRoute(ObservabilityPage);
  else if (matchPath("/reports/:reportId", pathname)) route = renderRoute(ReportsPage, { reportId: matchPath("/reports/:reportId", pathname)!.reportId });
  else if (pathname === "/reports") route = renderRoute(ReportsPage);
  else if (pathname === "/system" || pathname === "/system/connections") route = renderRoute(SystemPage, { view: "connections" });
  else if (pathname === "/system/policies") route = renderRoute(SystemPage, { view: "policies" });
  else if (pathname === "/system/settings") route = renderRoute(SystemPage, { view: "settings" });
  else if (pathname === "/manual") route = renderRoute(UserManualPage);
  else if (pathname === "/motion-lab/assembly") route = <Redirect to="/motion-lab/particle-core" />;
  else if (pathname === "/motion-lab/particle-core") route = renderRoute(ParticleCoreReviewPage);
  else if (pathname === "/motion-lab/particle-module-transition") route = renderRoute(ParticleModuleTransitionPage);
  else if (pathname === "/motion-lab/candidates") route = renderRoute(ModelCandidateReviewPage);
  else if (pathname === "/motion-lab/webgl") route = <Redirect to="/motion-lab/particle-core" />;
  else if (pathname === "/motion-lab") route = renderRoute(MotionLabPage);
  else route = <div className="os-page os-narrow-page"><PageHeader eyebrow="404" title="Ti-Scale surface not found" description="The requested route does not exist in Ti-Scale." actions={<ButtonLink href="/">Return to Overview</ButtonLink>} /></div>;
  return <Suspense fallback={<LoadingRoute />}>{route}</Suspense>;
}
