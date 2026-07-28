import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import ts from "typescript";

const SHA256 = /^[a-f0-9]{64}$/u;
const MIGRATION_FILE = /^(\d{3})_([a-z0-9_]+)\.ts$/u;
const REGISTRY_PATH = "server/db/migrations/index.ts" as const;

export interface ReleaseMigrationAttestationEntry {
  readonly version: number;
  readonly name: string;
  readonly exportName: string;
  readonly path: string;
  readonly sha256: string;
}

export interface ReleaseMigrationAttestation {
  readonly schemaVersion: "ti-scale.release-migration-attestation.v1";
  readonly targetSchema: number;
  readonly migrationCount: number;
  readonly registryPath: typeof REGISTRY_PATH;
  readonly registrySha256: string;
  readonly migrations: readonly ReleaseMigrationAttestationEntry[];
  readonly attestationSha256: string;
}

interface MigrationRegistryEntry {
  readonly exportName: string;
  readonly relativeImport: string;
}

function digest(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function containedBy(root: string, candidate: string): boolean {
  const child = relative(root, candidate);
  return child === "" || (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`));
}

function realDirectory(pathValue: string, label: string): string {
  const path = resolve(pathValue);
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || realpathSync(path) !== path) {
    throw new Error(`${label} must be a real directory without symbolic-link traversal`);
  }
  return path;
}

function readRealFile(root: string, pathValue: string, label: string): { readonly path: string; readonly bytes: Buffer } {
  const path = resolve(pathValue);
  if (!containedBy(root, path)) throw new Error(`${label} escapes the selected release source`);
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || realpathSync(path) !== path) {
    throw new Error(`${label} must be a real regular file`);
  }
  return { path, bytes: readFileSync(path) };
}

function parseTypeScript(path: string, bytes: Buffer, label: string): ts.SourceFile {
  const sourceFile = ts.createSourceFile(path, bytes.toString("utf8"), ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS);
  const diagnostics = (sourceFile as ts.SourceFile & { readonly parseDiagnostics: readonly ts.Diagnostic[] }).parseDiagnostics;
  if (diagnostics.length) {
    const detail = ts.flattenDiagnosticMessageText(diagnostics[0]!.messageText, " ");
    throw new Error(`${label} is not valid TypeScript: ${detail}`);
  }
  return sourceFile;
}

function exported(statement: ts.VariableStatement): boolean {
  return statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true;
}

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) || ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) || ts.isSatisfiesExpression(current)
  ) current = current.expression;
  return current;
}

function migrationArray(sourceFile: ts.SourceFile): readonly string[] {
  let initializer: ts.Expression | undefined;
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement) || !exported(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === "DATABASE_MIGRATIONS") {
        if (initializer) throw new Error("Migration registry exports DATABASE_MIGRATIONS more than once");
        initializer = declaration.initializer;
      }
    }
  }
  if (!initializer) throw new Error("Migration registry does not export DATABASE_MIGRATIONS");
  const outer = unwrap(initializer);
  if (
    !ts.isCallExpression(outer) || outer.arguments.length !== 1 ||
    !ts.isPropertyAccessExpression(outer.expression) ||
    !ts.isIdentifier(outer.expression.expression) || outer.expression.expression.text !== "Object" ||
    outer.expression.name.text !== "freeze"
  ) throw new Error("DATABASE_MIGRATIONS must be a literal Object.freeze array");
  const argument = unwrap(outer.arguments[0]!);
  if (!ts.isArrayLiteralExpression(argument)) throw new Error("DATABASE_MIGRATIONS must be a literal array");
  return argument.elements.map((element) => {
    const value = unwrap(element);
    if (!ts.isIdentifier(value)) throw new Error("DATABASE_MIGRATIONS may contain only imported migration identifiers");
    return value.text;
  });
}

function migrationImports(sourceFile: ts.SourceFile): ReadonlyMap<string, string> {
  const imports = new Map<string, string>();
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const relativeImport = statement.moduleSpecifier.text;
    const fileName = `${relativeImport.replace(/^\.\//u, "")}.ts`;
    if (!relativeImport.startsWith("./") || !MIGRATION_FILE.test(fileName)) continue;
    const bindings = statement.importClause?.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings) || bindings.elements.length !== 1) {
      throw new Error(`Migration import ${relativeImport} must import exactly one named export`);
    }
    const binding = bindings.elements[0]!;
    if (binding.propertyName || imports.has(binding.name.text)) {
      throw new Error(`Migration import ${relativeImport} must use one unique, unaliased export`);
    }
    imports.set(binding.name.text, relativeImport);
  }
  return imports;
}

function property(object: ts.ObjectLiteralExpression, name: string): ts.Expression {
  const matches = object.properties.filter((candidate): candidate is ts.PropertyAssignment =>
    ts.isPropertyAssignment(candidate) && (
      (ts.isIdentifier(candidate.name) && candidate.name.text === name) ||
      (ts.isStringLiteral(candidate.name) && candidate.name.text === name)
    ));
  if (matches.length !== 1) throw new Error(`Migration object must define exactly one literal ${name}`);
  return unwrap(matches[0]!.initializer);
}

function migrationMetadata(sourceFile: ts.SourceFile, exportName: string): { readonly version: number; readonly name: string } {
  let object: ts.ObjectLiteralExpression | undefined;
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement) || !exported(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== exportName || !declaration.initializer) continue;
      const initializer = unwrap(declaration.initializer);
      if (!ts.isObjectLiteralExpression(initializer) || object) {
        throw new Error(`Migration export ${exportName} must be one literal object`);
      }
      object = initializer;
    }
  }
  if (!object) throw new Error(`Migration file does not export ${exportName} as a literal object`);
  const versionValue = property(object, "version");
  const nameValue = property(object, "name");
  if (!ts.isNumericLiteral(versionValue)) throw new Error(`Migration ${exportName} version must be a numeric literal`);
  const version = Number(versionValue.text);
  if (!Number.isSafeInteger(version) || version <= 0) throw new Error(`Migration ${exportName} version is invalid`);
  if (!ts.isStringLiteral(nameValue) || !nameValue.text.trim()) throw new Error(`Migration ${exportName} name must be a non-empty string literal`);
  return { version, name: nameValue.text };
}

function attestationContent(value: Omit<ReleaseMigrationAttestation, "attestationSha256">): string {
  return JSON.stringify(value);
}

export function assertValidReleaseMigrationAttestation(value: unknown): ReleaseMigrationAttestation {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Release migration attestation must be an object");
  }
  const raw = value as Record<string, unknown>;
  if (
    raw.schemaVersion !== "ti-scale.release-migration-attestation.v1" ||
    !Number.isSafeInteger(raw.targetSchema) || (raw.targetSchema as number) <= 0 ||
    !Number.isSafeInteger(raw.migrationCount) || (raw.migrationCount as number) <= 0 ||
    raw.registryPath !== REGISTRY_PATH || typeof raw.registrySha256 !== "string" || !SHA256.test(raw.registrySha256) ||
    typeof raw.attestationSha256 !== "string" || !SHA256.test(raw.attestationSha256) || !Array.isArray(raw.migrations)
  ) throw new Error("Release migration attestation metadata is invalid");
  const migrations = raw.migrations.map((entryValue): ReleaseMigrationAttestationEntry => {
    if (!entryValue || typeof entryValue !== "object" || Array.isArray(entryValue)) {
      throw new Error("Release migration attestation entry is invalid");
    }
    const entry = entryValue as Record<string, unknown>;
    if (
      !Number.isSafeInteger(entry.version) || (entry.version as number) <= 0 ||
      typeof entry.name !== "string" || !entry.name.trim() ||
      typeof entry.exportName !== "string" || !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(entry.exportName) ||
      typeof entry.path !== "string" || !/^server\/db\/migrations\/\d{3}_[a-z0-9_]+\.ts$/u.test(entry.path) ||
      typeof entry.sha256 !== "string" || !SHA256.test(entry.sha256)
    ) throw new Error("Release migration attestation entry metadata is invalid");
    return {
      version: entry.version as number,
      name: entry.name,
      exportName: entry.exportName,
      path: entry.path,
      sha256: entry.sha256,
    };
  });
  if (migrations.length !== raw.migrationCount || migrations.at(-1)?.version !== raw.targetSchema) {
    throw new Error("Release migration attestation aggregate is inconsistent");
  }
  let previous = 0;
  const names = new Set<string>();
  const paths = new Set<string>();
  for (const migration of migrations) {
    if (migration.version <= previous || names.has(migration.name) || paths.has(migration.path)) {
      throw new Error("Release migration attestation entries must be ordered and unique");
    }
    const prefix = Number(migration.path.split("/").at(-1)!.slice(0, 3));
    if (prefix !== migration.version) throw new Error("Release migration path does not match its version");
    previous = migration.version;
    names.add(migration.name);
    paths.add(migration.path);
  }
  const content = {
    schemaVersion: "ti-scale.release-migration-attestation.v1" as const,
    targetSchema: raw.targetSchema as number,
    migrationCount: raw.migrationCount as number,
    registryPath: REGISTRY_PATH,
    registrySha256: raw.registrySha256,
    migrations,
  };
  if (digest(attestationContent(content)) !== raw.attestationSha256) {
    throw new Error("Release migration attestation checksum is invalid");
  }
  return { ...content, attestationSha256: raw.attestationSha256 };
}

/**
 * Determines the migration ceiling without importing or executing candidate
 * code. The registry and every selected migration are parsed as TypeScript,
 * content-hashed, and reduced into one portable attestation that is identical
 * for the mutable source and its immutable staged copy.
 */
export function attestReleaseMigrationCeiling(sourceRootValue: string): ReleaseMigrationAttestation {
  const sourceRoot = realDirectory(realpathSync(resolve(sourceRootValue)), "Release source root");
  const migrationsRoot = realDirectory(join(sourceRoot, "server", "db", "migrations"), "Release migrations directory");
  const registry = readRealFile(sourceRoot, join(migrationsRoot, "index.ts"), "Migration registry");
  const registrySource = parseTypeScript(registry.path, registry.bytes, "Migration registry");
  const imports = migrationImports(registrySource);
  const orderedExports = migrationArray(registrySource);
  if (!orderedExports.length || new Set(orderedExports).size !== orderedExports.length) {
    throw new Error("Migration registry must contain unique migration identifiers");
  }

  const discovered = readdirSync(migrationsRoot).filter((name) => MIGRATION_FILE.test(name)).sort();
  const selectedPaths = orderedExports.map((exportName): MigrationRegistryEntry => {
    const relativeImport = imports.get(exportName);
    if (!relativeImport) throw new Error(`Migration registry entry ${exportName} has no matching migration import`);
    return { exportName, relativeImport };
  });
  const selectedFiles = selectedPaths.map(({ relativeImport }) => `${relativeImport.slice(2)}.ts`).sort();
  if (JSON.stringify(discovered) !== JSON.stringify(selectedFiles) || imports.size !== orderedExports.length) {
    throw new Error("Migration registry and migration files do not form one exact set");
  }

  const migrations = selectedPaths.map(({ exportName, relativeImport }): ReleaseMigrationAttestationEntry => {
    const fileName = `${relativeImport.slice(2)}.ts`;
    const match = MIGRATION_FILE.exec(fileName)!;
    const file = readRealFile(sourceRoot, join(migrationsRoot, fileName), `Migration ${fileName}`);
    const metadata = migrationMetadata(parseTypeScript(file.path, file.bytes, `Migration ${fileName}`), exportName);
    if (metadata.version !== Number(match[1])) throw new Error(`Migration ${fileName} version does not match its filename`);
    return {
      version: metadata.version,
      name: metadata.name,
      exportName,
      path: `server/db/migrations/${fileName}`,
      sha256: digest(file.bytes),
    };
  });

  let previous = 0;
  const names = new Set<string>();
  for (const migration of migrations) {
    if (migration.version <= previous || names.has(migration.name)) {
      throw new Error("Migration registry versions and names must be ordered and unique");
    }
    previous = migration.version;
    names.add(migration.name);
  }
  const content = {
    schemaVersion: "ti-scale.release-migration-attestation.v1" as const,
    targetSchema: migrations.at(-1)!.version,
    migrationCount: migrations.length,
    registryPath: REGISTRY_PATH,
    registrySha256: digest(registry.bytes),
    migrations,
  };
  return assertValidReleaseMigrationAttestation({
    ...content,
    attestationSha256: digest(attestationContent(content)),
  });
}

export function assertReleaseMigrationAttestationsMatch(
  expectedValue: unknown,
  actualValue: unknown,
  label = "Staged release migration attestation",
): ReleaseMigrationAttestation {
  const expected = assertValidReleaseMigrationAttestation(expectedValue);
  const actual = assertValidReleaseMigrationAttestation(actualValue);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} does not match the selected source migration attestation`);
  }
  return actual;
}
