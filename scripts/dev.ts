const commands: string[][] = [
  [process.execPath, "run", "server:dev"],
  [process.execPath, "run", "client:dev"],
];

const children = commands.map((command) => Bun.spawn(command, {
  cwd: import.meta.dir + "/..",
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
  env: process.env,
}));

let stopping = false;

async function stop(exitCode: number, signal: NodeJS.Signals = "SIGTERM"): Promise<void> {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    if (child.exitCode === null) child.kill(signal);
  }
  await Promise.allSettled(children.map((child) => child.exited));
  process.exit(exitCode);
}

process.once("SIGINT", () => void stop(130, "SIGINT"));
process.once("SIGTERM", () => void stop(143, "SIGTERM"));

const firstExit = await Promise.race(children.map(async (child) => ({
  child,
  exitCode: await child.exited,
})));

await stop(firstExit.exitCode);
