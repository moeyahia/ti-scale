#!/usr/bin/env bun
import { writeFileSync } from "node:fs";

const readyPath = process.argv[2];
if (!readyPath) process.exit(64);

writeFileSync(readyPath, `${JSON.stringify({
  pid: process.pid,
  startedAt: new Date().toISOString(),
})}\n`, { mode: 0o600 });

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));
setInterval(() => undefined, 1_000);
