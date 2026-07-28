export const GUIDED_RECONNAISSANCE_REGISTRY_VERSION = 1 as const;
export const MAX_GUIDED_TCP_PORTS = 1_024 as const;

export const GUIDED_TCP_PORT_PRESETS = [
  {
    id: "focused_services",
    version: 1,
    label: "Focused service baseline",
    description: "Checks a small cross-platform set of common web, file-sharing, remote-access, and management services.",
    ports: [22, 80, 135, 139, 443, 445, 3389, 5985, 5986, 8080, 8443],
  },
  {
    id: "web_services",
    version: 1,
    label: "Web application services",
    description: "Checks common HTTP and HTTPS listener ports without crawling, authentication attempts, or exploit scripts.",
    ports: [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443],
  },
  {
    id: "remote_management",
    version: 1,
    label: "Remote management services",
    description: "Checks common SSH, Windows remote-management, file-sharing, and remote-desktop listener ports.",
    ports: [22, 135, 139, 445, 3389, 5985, 5986],
  },
] as const;

export type GuidedTcpPortPresetId = (typeof GUIDED_TCP_PORT_PRESETS)[number]["id"];

export type GuidedReconnaissanceSelection =
  | Readonly<{
      readonly mode: "host_liveness";
    }>
  | Readonly<{
      readonly mode: "tcp_service_scan";
      readonly portSelection: Readonly<{
        readonly source: "preset" | "custom";
        readonly presetId?: GuidedTcpPortPresetId;
        readonly presetVersion?: number;
        readonly ports: readonly number[];
      }>;
    }>;

export interface GuidedReconnaissanceParseResult {
  readonly selection?: GuidedReconnaissanceSelection;
  readonly issues: readonly string[];
}
function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function canonicalPorts(value: unknown, label: string, issues: string[]): number[] {
  if (!Array.isArray(value) || value.length === 0) {
    issues.push(`${label} must contain at least one individual TCP port.`);
    return [];
  }
  if (value.length > MAX_GUIDED_TCP_PORTS) {
    issues.push(`${label} may contain at most ${MAX_GUIDED_TCP_PORTS} individual TCP ports.`);
  }
  const ports = value.flatMap((candidate, index) => {
    if (!Number.isSafeInteger(candidate) || Number(candidate) < 1 || Number(candidate) > 65_535) {
      issues.push(`${label}[${index}] must be a whole number from 1 through 65535. Use individual ports such as 22, 80, and 443; ranges are not accepted.`);
      return [];
    }
    return [Number(candidate)];
  });
  return [...new Set(ports)].sort((left, right) => left - right).slice(0, MAX_GUIDED_TCP_PORTS);
}

/**
 * Parses the optional, operator-selected first Guided reconnaissance step.
 * Missing input intentionally preserves the existing target-derived behavior.
 */
export function parseGuidedReconnaissanceSelection(
  value: unknown,
  label = "guidedReconnaissance",
): GuidedReconnaissanceParseResult {
  if (value === undefined) return { issues: [] };
  const issues: string[] = [];
  const root = object(value);
  if (!root) return { issues: [`${label} must be a structured object.`] };
  if (root.mode === "host_liveness") {
    if (root.portSelection !== undefined) {
      issues.push(`${label}.portSelection is only valid when the first represented step is a TCP service scan.`);
    }
    return issues.length > 0
      ? { issues }
      : { selection: { mode: "host_liveness" }, issues };
  }
  if (root.mode !== "tcp_service_scan") {
    return { issues: [`${label}.mode must be host_liveness or tcp_service_scan.`] };
  }
  const portSelection = object(root.portSelection);
  if (!portSelection) {
    return { issues: [`${label}.portSelection is required for a TCP service scan. Choose a reviewed preset or enter individual ports such as 22, 80, 443.`] };
  }
  if (portSelection.source !== "preset" && portSelection.source !== "custom") {
    issues.push(`${label}.portSelection.source must be preset or custom.`);
  }
  const ports = canonicalPorts(portSelection.ports, `${label}.portSelection.ports`, issues);
  if (portSelection.source === "preset") {
    const preset = GUIDED_TCP_PORT_PRESETS.find(({ id }) => id === portSelection.presetId);
    if (!preset) {
      issues.push(`${label}.portSelection.presetId must name a reviewed TCP-port preset from registry version ${GUIDED_RECONNAISSANCE_REGISTRY_VERSION}.`);
    } else {
      if (portSelection.presetVersion !== preset.version) {
        issues.push(`${label}.portSelection.presetVersion must be ${preset.version} for ${preset.id}. Refresh the intake registry and select the preset again.`);
      }
      if (ports.join(",") !== preset.ports.join(",")) {
        issues.push(`${label}.portSelection.ports does not match reviewed preset ${preset.id} v${preset.version}. Refresh the intake registry or choose Custom ports.`);
      }
    }
  } else if (portSelection.presetId !== undefined || portSelection.presetVersion !== undefined) {
    issues.push(`${label} custom ports cannot claim a reviewed preset ID or version. Remove the preset fields or select that preset.`);
  }
  if (issues.length > 0) return { issues };
  return {
    selection: {
      mode: "tcp_service_scan",
      portSelection: portSelection.source === "preset"
        ? {
            source: "preset",
            presetId: portSelection.presetId as GuidedTcpPortPresetId,
            presetVersion: portSelection.presetVersion as number,
            ports,
          }
        : { source: "custom", ports },
    },
    issues,
  };
}
