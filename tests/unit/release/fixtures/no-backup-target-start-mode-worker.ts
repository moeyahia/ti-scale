#!/usr/bin/env bun
import { noBackupTargetStartMode } from
  "../../../../scripts/release/NoBackupPreviewRelease";
import { readFunctionalReleaseTransactionJournal } from
  "../../../../scripts/release/DurableReleaseTransaction";

const journalDirectory = process.argv[2];
if (!journalDirectory) {
  process.stderr.write("missing journal directory\n");
  process.exit(64);
}

process.stdout.write(`${noBackupTargetStartMode(
  readFunctionalReleaseTransactionJournal(journalDirectory),
)}\n`);
