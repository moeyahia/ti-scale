import type { ReactNode } from "react";
import { QueryProvider } from "../../data/cache/QueryProvider";
import { EventStreamProvider } from "../../data/events/EventStreamProvider";
import { AuthProvider } from "./AuthProvider";

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <QueryProvider>
      <AuthProvider>
        <EventStreamProvider>{children}</EventStreamProvider>
      </AuthProvider>
    </QueryProvider>
  );
}
