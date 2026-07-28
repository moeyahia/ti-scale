import {
  PublicNvdHttpSidecar,
  resolvePublicNvdHttpPort,
  resolvePublicNvdTokenFilePath,
} from "./PublicNvdHttpSidecar";

export async function runPublicNvdHttpSidecar(): Promise<PublicNvdHttpSidecar> {
  const sidecar = new PublicNvdHttpSidecar({
    tokenFilePath: resolvePublicNvdTokenFilePath(
      process.env.TI_SCALE_PUBLIC_NVD_MCP_TOKEN_FILE,
    ),
    port: resolvePublicNvdHttpPort(process.env.TI_SCALE_PUBLIC_NVD_MCP_PORT),
  });
  await sidecar.start();
  return sidecar;
}

if (import.meta.main) {
  runPublicNvdHttpSidecar().then((sidecar) => {
    let stopping = false;
    const stop = async () => {
      if (stopping) return;
      stopping = true;
      await sidecar.stop();
      process.exitCode = 0;
    };
    process.once("SIGINT", () => { void stop(); });
    process.once("SIGTERM", () => { void stop(); });
  }).catch(() => {
    process.stderr.write("Ti-Scale public NVD MCP HTTP sidecar failed safely.\n");
    process.exitCode = 1;
  });
}
