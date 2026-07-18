export type JsonRecord = Record<string, unknown>;

export function object(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as JsonRecord;
}

export function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

export function string(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  return value;
}

export function nonEmpty(value: unknown, label: string): string {
  const result = string(value, label);
  if (!result.trim()) throw new Error(`${label} cannot be empty`);
  return result;
}

export function nullableString(value: unknown, label: string): string | null {
  return value === null || value === undefined ? null : string(value, label);
}

export function number(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${label} must be a finite number`);
  return value;
}

export function nullableNumber(value: unknown, label: string): number | null {
  return value === null || value === undefined ? null : number(value, label);
}

export function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be boolean`);
  return value;
}

export function schema(value: JsonRecord): void {
  if (value.schemaVersion !== "2.4") throw new Error("unsupported Ti-Scale schema version");
}

export function stringList(value: unknown, label: string): string[] {
  return array(value, label).map((item, index) => string(item, `${label}[${index}]`));
}
