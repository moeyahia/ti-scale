import { type ReactNode, useCallback, useState } from "react";
import { QueryProvider } from "../../data/cache/QueryProvider";
import { EventStreamProvider } from "../../data/events/EventStreamProvider";
import { BootSequence, type BootReadiness } from "../boot/BootSequence";
import { AuthProvider } from "./AuthProvider";

export function AppProviders({ children }: { children: ReactNode }) {
  const [bootReadiness, setBootReadiness] = useState<BootReadiness>({
    ready: false,
    status: "Verifying protected operator session",
    next: "Command Center",
  });
  const updateBootReadiness = useCallback((readiness: BootReadiness) => {
    setBootReadiness(readiness);
  }, []);

  return (
    <QueryProvider>
      <BootSequence readiness={bootReadiness}>
        <AuthProvider onStartupReadinessChange={updateBootReadiness}>
          <EventStreamProvider>{children}</EventStreamProvider>
        </AuthProvider>
      </BootSequence>
    </QueryProvider>
  );
}
