process.on("SIGTERM", () => process.exit(0));
setInterval(() => undefined, 10_000);
