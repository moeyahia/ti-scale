import { createDatabaseConnection, checkDatabaseIntegrity } from "../db";

const databasePath = process.argv[2];
if (!databasePath) {
  process.stderr.write("Startup database integrity child requires one database path\n");
  process.exit(2);
}

try {
  const database = createDatabaseConnection({
    filename: databasePath,
    readonly: true,
    fileMustExist: true,
    verifyIntegrity: false,
  });
  try {
    const result = checkDatabaseIntegrity(database);
    process.stdout.write(`${JSON.stringify({
      schemaVersion: "ti-scale.startup-database-integrity.v1",
      ok: result.ok,
      messages: result.messages,
    })}\n`);
  } finally {
    database.close();
  }
} catch (error) {
  process.stderr.write(
    `Startup database integrity child failed: ${error instanceof Error ? error.name : "UnknownError"}\n`,
  );
  process.exitCode = 1;
}
