export class NotificationApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly humanMessage: string,
    readonly category: string,
    readonly remediation?: string,
  ) {
    super(message);
    this.name = "NotificationApiError";
  }
}
