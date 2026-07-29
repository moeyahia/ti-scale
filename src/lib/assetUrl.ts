/** Resolve Ti-Scale-owned static media against this application's Vite base. */
export function assetUrl(path: string): string {
  const configuredBase = import.meta.env.BASE_URL ?? "/";
  const base = configuredBase.endsWith("/")
    ? configuredBase
    : `${configuredBase}/`;
  return `${base}${path.replace(/^\/+/, "")}`;
}
