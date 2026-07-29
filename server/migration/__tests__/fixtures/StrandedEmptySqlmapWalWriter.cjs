"use strict";

const Database = require("better-sqlite3");

const path = process.argv[2];
if (!path) throw new Error("A SQLite path is required");

const database = new Database(path);
database.pragma("journal_mode = WAL");
database.pragma("wal_autocheckpoint = 0");
database.exec("CREATE TABLE storage (id INTEGER PRIMARY KEY, value TEXT)");
database.pragma("wal_checkpoint(TRUNCATE)");
database.exec(`
  BEGIN IMMEDIATE;
  INSERT INTO storage (id, value) VALUES (1, 'transient');
  DELETE FROM storage WHERE id = 1;
  COMMIT;
`);

process.stdout.write("STRANDED_EMPTY_SQLMAP_WAL_READY\n");
setInterval(() => undefined, 1_000);
