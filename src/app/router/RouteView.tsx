import { lazy, Suspense, type ReactNode, useEffect } from "react";
import { ButtonLink, LoadingPanel, PageHeader } from "../../design-system/components/Primitives";
import { matchPath, useNavigation } from "./navigation";

const OverviewPage = lazy(() => import("../../features/overview/OverviewPage"));
const MissionPortfolioPage = lazy(() => import("../../features/missions/MissionPortfolioPage"));
const JourneySelectionPage = lazy(() => import("../../features/missions/JourneySelectionPage"));
const AutonomousContractPage = lazy(() => import("../../features/missions/AutonomousContractPage"));
const GuidedMissionCreatePage = lazy(() => import("../../features/missions/GuidedMissionCreatePage"));
const BrainHomePage = lazy(() => import("../../features/brain/BrainHomePage"));
const BrainGraphPage = lazy(() => import("../../features/brain/BrainGraphPage"));
const BrainInboxPage = lazy(() => import("../../features/brain/BrainInboxPage"));
const BrainNodePage = lazy(() => import("../../features/brain/BrainNodePage"));
const BrainControlPage = lazy(() => import("../../features/brain/BrainControlPage"));
const BrainVaultPage = lazy(() => import("../../features/brain/BrainVaultPage"));
const AgentsPage = lazy(() => import("../../features/agents/AgentsPage"));
const IntelligencePage = lazy(() => import("../../features/intelligence/IntelligencePage"));
const ObservabilityPage = lazy(() => import("../../features/observability/ObservabilityPage"));
const LearningPage = lazy(() => import("../../features/learning/LearningPage"));
const ReportsPage = lazy(() => import("../../features/reports/ReportsPage"));
const SystemPage = lazy(() => import("../../features/system/SystemPage"));
const DecisionsPage = lazy(() => import("../../features/decisions/DecisionsPage"));
const LiveOperationsPage = lazy(() => import("../../features/live-operations/LiveOperationsPage"));
const GuidedWorkspacePage = lazy(() => import("../../features/guided/GuidedWorkspacePage"));
const RunWorkspacePage = lazy(() => import("../../features/runs/RunWorkspacePage"));
const UserManualPage = lazy(() => import("../../features/manual/UserManualPage"));

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
  let route: ReactNode;
  if (pathname === "/") route = <OverviewPage />;
  else if (pathname === "/missions") route = <MissionPortfolioPage />;
  else if (pathname === "/missions/new") route = <JourneySelectionPage />;
  else if (pathname === "/missions/new/autonomous") route = <AutonomousContractPage />;
  else if (pathname === "/missions/new/guided") route = <GuidedMissionCreatePage />;
  else if (matchPath("/missions/:missionId/runs/:runId", pathname)) { const params = matchPath("/missions/:missionId/runs/:runId", pathname)!; route = <RunWorkspacePage missionId={params.missionId} runId={params.runId} />; }
  else if (matchPath("/missions/:missionId", pathname)) route = <RunWorkspacePage missionId={matchPath("/missions/:missionId", pathname)!.missionId} />;
  else if (matchPath("/guided/:missionId", pathname)) route = <GuidedWorkspacePage missionId={matchPath("/guided/:missionId", pathname)!.missionId} />;
  else if (pathname === "/guided") route = <GuidedWorkspacePage />;
  else if (matchPath("/live/:runId", pathname)) route = <LiveOperationsPage runId={matchPath("/live/:runId", pathname)!.runId} />;
  else if (pathname === "/live") route = <LiveOperationsPage />;
  else if (pathname === "/decisions") route = <DecisionsPage />;
  else if (pathname === "/approvals") route = <Redirect to="/decisions" />;
  else if (pathname === "/intelligence") route = <Redirect to="/intelligence/evidence" />;
  else if (matchPath("/intelligence/evidence/:id", pathname)) route = <IntelligencePage view="evidence" selectedId={matchPath("/intelligence/evidence/:id", pathname)!.id} />;
  else if (matchPath("/intelligence/findings/:id", pathname)) route = <IntelligencePage view="findings" selectedId={matchPath("/intelligence/findings/:id", pathname)!.id} />;
  else if (matchPath("/intelligence/artifacts/:id", pathname)) route = <IntelligencePage view="artifacts" selectedId={matchPath("/intelligence/artifacts/:id", pathname)!.id} />;
  else if (pathname === "/intelligence/evidence") route = <IntelligencePage view="evidence" />;
  else if (pathname === "/intelligence/findings") route = <IntelligencePage view="findings" />;
  else if (pathname === "/intelligence/artifacts") route = <IntelligencePage view="artifacts" />;
  else if (matchPath("/agents/:agentId", pathname)) route = <AgentsPage agentId={matchPath("/agents/:agentId", pathname)!.agentId} />;
  else if (pathname === "/agents") route = <AgentsPage />;
  else if (pathname === "/brain") route = <BrainHomePage />;
  else if (pathname === "/brain/graph") route = <BrainGraphPage />;
  else if (pathname === "/brain/inbox") route = <BrainInboxPage />;
  else if (pathname === "/brain/control") route = <BrainControlPage />;
  else if (pathname === "/brain/vault") route = <BrainVaultPage />;
  else if (matchPath("/brain/nodes/:memoryNodeId", pathname)) route = <BrainNodePage nodeId={matchPath("/brain/nodes/:memoryNodeId", pathname)!.memoryNodeId} />;
  else if (matchPath("/learning/lessons/:lessonId", pathname)) route = <LearningPage selectedLessonId={matchPath("/learning/lessons/:lessonId", pathname)!.lessonId} />;
  else if (pathname === "/research") route = <Redirect to="/learning?view=research" />;
  else if (pathname === "/learning") route = <LearningPage />;
  else if (pathname === "/observability") route = <ObservabilityPage />;
  else if (matchPath("/reports/:reportId", pathname)) route = <ReportsPage reportId={matchPath("/reports/:reportId", pathname)!.reportId} />;
  else if (pathname === "/reports") route = <ReportsPage />;
  else if (pathname === "/system" || pathname === "/system/connections") route = <SystemPage view="connections" />;
  else if (pathname === "/system/policies") route = <SystemPage view="policies" />;
  else if (pathname === "/system/settings") route = <SystemPage view="settings" />;
  else if (pathname === "/manual") route = <UserManualPage />;
  else route = <div className="os-page os-narrow-page"><PageHeader eyebrow="404" title="Ti-Scale surface not found" description="The requested route does not exist in Ti-Scale." actions={<ButtonLink href="/">Return to Overview</ButtonLink>} /></div>;
  return <Suspense fallback={<LoadingRoute />}>{route}</Suspense>;
}
