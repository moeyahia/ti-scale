"use strict";

const Database = require("better-sqlite3");

const path = process.argv[2];
if (!path) throw new Error("A SQLite path is required");

const database = new Database(path);
database.pragma("foreign_keys = ON");
database.pragma("journal_mode = WAL");
database.pragma("wal_autocheckpoint = 0");
database.exec(`
  CREATE TABLE parent (
    id INTEGER PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE child (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER NOT NULL REFERENCES parent(id),
    value TEXT NOT NULL
  );
  INSERT INTO parent (id, value) VALUES (1, 'checkpointed-base');
`);
database.pragma("wal_checkpoint(TRUNCATE)");
database.exec(`
  INSERT INTO parent (id, value) VALUES (2, 'committed-only-in-wal');
  INSERT INTO child (id, parent_id, value)
  VALUES (1, 2, 'depends-on-committed-wal-row');
`);

process.stdout.write("STRANDED_WAL_READY\n");
setInterval(() => undefined, 1_000);
