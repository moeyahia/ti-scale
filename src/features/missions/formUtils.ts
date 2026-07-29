export function lines(value: string): string[] {
  return value.split("\n").map((item) => item.trim()).filter(Boolean);
}

export function optionalPositive(value: string): number | undefined {
  if (!value.trim()) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

export function requestKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `mission-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function safeNextUrl(value: string, fallback: string): string {
  return value.startsWith("/") && !value.startsWith("//") && !value.includes("\\") ? value : fallback;
}
