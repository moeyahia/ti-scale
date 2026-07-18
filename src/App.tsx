import { RouteErrorBoundary } from "./app/ErrorBoundary";
import { AppProviders } from "./app/providers/AppProviders";
import { NavigationProvider, useNavigation } from "./app/router/navigation";
import { RouteView } from "./app/router/RouteView";
import { AppShell } from "./app/shell/AppShell";
import "./design-system/tokens/ti-scale.css";
import "./design-system/tokens/feature-surfaces.css";

function ApplicationRoute() {
  const { pathname } = useNavigation();
  return (
    <AppProviders>
      <AppShell>
        <RouteErrorBoundary resetKey={pathname}>
          <RouteView />
        </RouteErrorBoundary>
      </AppShell>
    </AppProviders>
  );
}

export default function App() {
  return (
    <NavigationProvider>
      <ApplicationRoute />
    </NavigationProvider>
  );
}
