import { isAbsolute, resolve } from "node:path";
import {
  DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED,
  seedDisposableCandidateLinuxProof,
} from "../server/autonomous-runtime";
import {
  createDatabaseConnection,
} from "../server/db";

function argumentsFrom(argv: readonly string[]): Readonly<{
  databasePath: string;
  scriptSourceRoot?: string;
}> {
  if (!argv.includes("--execute")) {
    throw new Error(
      "Registration is explicit: add --execute. This command creates no backup.",
    );
  }
  const databaseIndex = argv.indexOf("--database-path");
  const databasePath = databaseIndex >= 0 ? argv[databaseIndex + 1] : undefined;
  const sourceIndex = argv.indexOf("--script-source-root");
  const scriptSourceRoot = sourceIndex >= 0 ? argv[sourceIndex + 1] : undefined;
  const allowed = new Set([
    "--execute",
    "--database-path",
    "--script-source-root",
  ]);
  for (const value of argv) {
    if (value.startsWith("--") && !allowed.has(value)) {
      throw new Error(`Unsupported argument ${value}`);
    }
  }
  if (!databasePath || !isAbsolute(databasePath)) {
    throw new Error("--database-path must be an absolute existing database");
  }
  if (scriptSourceRoot && !isAbsolute(scriptSourceRoot)) {
    throw new Error("--script-source-root must be absolute");
  }
  return Object.freeze({
    databasePath: resolve(databasePath),
    ...(scriptSourceRoot
      ? { scriptSourceRoot: resolve(scriptSourceRoot) }
      : {}),
  });
}

const input = argumentsFrom(process.argv.slice(2));
const database = createDatabaseConnection({
  filename: input.databasePath,
  fileMustExist: true,
  verifyIntegrity: true,
});
try {
  const schema = database.prepare(`
    SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations
  `).get() as { readonly version: number };
  if (schema.version < 46) {
    throw new Error("Schema 46 is required before fixture registration");
  }
  const receipt = seedDisposableCandidateLinuxProof({
    database,
    databasePath: input.databasePath,
    ...(input.scriptSourceRoot
      ? { scriptSourceRoot: input.scriptSourceRoot }
      : {}),
  });
  process.stdout.write(`${JSON.stringify({
    ...receipt,
    backupCreated: false,
    registrationAuthority: {
      fixtureOnly: true,
      realTargetSupport: false,
      productionPathProofOnly: true,
      postExploitSpecId:
        DISPOSABLE_CANDIDATE_LINUX_PROOF_SEED.postExploitSpecId,
    },
  }, null, 2)}\n`);
} finally {
  database.close();
}
