import type { RuntimeSourceManifests } from "../domain";
import {
  GUIDED_RECONNAISSANCE_REGISTRY_VERSION,
  GUIDED_TCP_PORT_PRESETS,
  MAX_GUIDED_TCP_PORTS,
} from "../missions/GuidedReconnaissance";
import type { IntakeRegistrySnapshot } from "./types";

const HOST_LIVENESS_TOOL_ID = "kali:ping-host-liveness";
const TCP_SERVICE_SCAN_TOOL_ID = "kali:nmap-tcp-connect-service-scan";

function readiness(
  manifests: RuntimeSourceManifests,
  toolId: string,
  ready: string,
  unavailable: string,
): Pick<IntakeRegistrySnapshot["guidedReconnaissance"]["modes"][number], "readiness" | "readinessExplanation"> {
  const tool = manifests.tools.find(({ id }) => id === toolId);
  return tool?.available
    ? { readiness: "ready", readinessExplanation: ready }
    : { readiness: "unavailable", readinessExplanation: tool ? unavailable : `${unavailable} The capability is not present in the current runtime projection.` };
}

export function buildGuidedReconnaissanceRegistry(
  manifests: RuntimeSourceManifests,
): IntakeRegistrySnapshot["guidedReconnaissance"] {
  return {
    registryVersion: GUIDED_RECONNAISSANCE_REGISTRY_VERSION,
    modes: [
      {
        id: "host_liveness",
        label: "Check host reachability",
        description: "Send two bounded reachability probes to the exact approved host before choosing deeper service checks. A timeout may mean filtering, not necessarily an offline host.",
        toolId: HOST_LIVENESS_TOOL_ID,
        ...readiness(
          manifests,
          HOST_LIVENESS_TOOL_ID,
          "The reviewed reachability tool has a current activation receipt.",
          "The reviewed reachability tool does not have a complete, current activation receipt.",
        ),
        remediation: "Keep the step manual, or restore the reviewed ping binding and obtain a fresh local activation receipt.",
        manualFallbackAvailable: true,
      },
      {
        id: "tcp_service_scan",
        label: "Scan selected TCP services",
        description: "Check only the listed individual TCP ports on one approved host and identify responding service versions. It does not use ranges, raw sockets, scripts, OS detection, or exploit checks.",
        toolId: TCP_SERVICE_SCAN_TOOL_ID,
        ...readiness(
          manifests,
          TCP_SERVICE_SCAN_TOOL_ID,
          "The exact reviewed Nmap binary and all local execution boundaries have a current activation receipt.",
          "The exact reviewed Nmap binary is not installed, enabled, and attested for this runtime.",
        ),
        remediation: "Guided can still launch with a represented manual step. Agent execution becomes available only after the exact reviewed Nmap binary is installed, the manifest capability is explicitly enabled, and a fresh activation receipt passes every local boundary check.",
        manualFallbackAvailable: true,
      },
    ],
    tcpPortPresets: GUIDED_TCP_PORT_PRESETS.map((preset) => ({
      ...preset,
      ports: [...preset.ports],
    })),
    customPorts: {
      maximumIndividualPorts: MAX_GUIDED_TCP_PORTS,
      example: "22, 80, 443, 8080",
      explanation: "Enter comma-separated individual ports from 1 through 65535. Ranges, service names, options, duplicates, and more than 1,024 ports are rejected. Ti-Scale stores a unique ascending list.",
    },
  };
}
