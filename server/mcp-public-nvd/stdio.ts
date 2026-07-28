import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createPublicNvdMcpServer } from "./PublicNvdMcpServer";

export async function runPublicNvdStdioSidecar(): Promise<void> {
  const server = createPublicNvdMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

if (import.meta.main) {
  runPublicNvdStdioSidecar().catch(() => {
    process.stderr.write("Ti-Scale public NVD MCP sidecar failed safely.\n");
    process.exitCode = 1;
  });
}
