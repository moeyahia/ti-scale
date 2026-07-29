export interface LocalSessionState {
  readonly schemaVersion: "2.4";
  readonly configured: boolean;
  readonly authenticated: boolean;
  readonly actorId?: string;
  readonly expiresAt?: string;
}
