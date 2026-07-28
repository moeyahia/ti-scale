import {
  readFileSync,
  rmSync,
} from "node:fs";
import { resolve } from "node:path";
import { validateTestPolicy } from "./validate-test-policy";

if ((process.geteuid?.() ?? process.getuid?.() ?? -1) !== 0) {
  throw new Error(
    "The complete release unit gate requires root so root-owned runtime and Unix-socket boundaries execute instead of being skipped",
  );
}

validateTestPolicy();

const reportPath = resolve(
  "/tmp",
  `ti-scale-bun-release-${String(process.pid)}-${String(Date.now())}.xml`,
);
try {
  const child = Bun.spawn([
    process.execPath,
    "test",
    "tests/unit",
    "server",
    "src/lib",
    "scripts/release/__tests__",
    "--no-orphans",
    "--max-concurrency=4",
    "--reporter=junit",
    `--reporter-outfile=${reportPath}`,
  ], {
    cwd: resolve(import.meta.dir, ".."),
    env: {
      PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
      HOME: process.env.HOME ?? "/root",
      TMPDIR: process.env.TMPDIR ?? "/tmp",
      TZ: "UTC",
      CI: process.env.CI ?? "true",
    },
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });
  const exitCode = await child.exited;
  const report = readFileSync(reportPath, "utf8");
  const summary = report.match(
    /<testsuites\b[^>]*\btests="(\d+)"[^>]*\bfailures="(\d+)"[^>]*\bskipped="(\d+)"/u,
  );
  if (!summary) {
    throw new Error("Bun did not produce a readable JUnit release summary");
  }
  const [, tests, failures, skipped] = summary;
  if (exitCode !== 0 || Number(failures) !== 0 || Number(skipped) !== 0) {
    process.stderr.write(
      `Bounded JUnit failure detail:\n${report.slice(0, 20_000)}\n`,
    );
    throw new Error(
      `Bun release test policy failed: exit=${String(exitCode)}, tests=${tests}, `
        + `failures=${failures}, skipped=${skipped}`,
    );
  }
  if (Number(tests) === 0) throw new Error("Bun release test policy discovered zero tests");
  console.log(
    `Bun release test gate passed: ${tests} tests, zero failures, zero skips`,
  );
} finally {
  rmSync(reportPath, { force: true });
}
