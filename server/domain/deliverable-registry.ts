import { DELIVERABLE_IDS, type DeliverableId } from "./catalog-ids";
import type {
  DeliverableCapabilityMapping,
  RuntimeCapabilityProjection,
} from "./source-manifest-adapters";

export interface DeliverableDefinition {
  readonly id: DeliverableId;
  readonly label: string;
  readonly purpose: string;
  readonly formats: readonly string[];
  readonly sensitivityNotes: string;
}

export interface RegisteredDeliverable extends DeliverableDefinition {
  readonly capability: DeliverableCapabilityMapping;
}

export interface DeliverableRegistry {
  readonly deliverables: Readonly<Record<DeliverableId, RegisteredDeliverable>>;
}

const deliverable = (
  id: DeliverableId,
  label: string,
  purpose: string,
  formats: readonly string[],
  sensitivityNotes: string,
): DeliverableDefinition => ({ id, label, purpose, formats, sensitivityNotes });

export const DELIVERABLE_DEFINITIONS: readonly DeliverableDefinition[] = [
  deliverable(
    "executive_summary",
    "Executive summary",
    "Summarize outcomes, impact, confidence, and the most important next actions.",
    ["Markdown", "HTML", "PDF"],
    "Avoid unnecessary technical secrets or target identifiers.",
  ),
  deliverable(
    "technical_findings",
    "Technical findings",
    "Document evidence-linked weaknesses, impact, validation, and remediation.",
    ["Markdown", "HTML", "PDF", "JSON"],
    "May contain sensitive reproduction details.",
  ),
  deliverable(
    "network_asset_map",
    "Network and asset map",
    "Export the evidence-backed recon digital twin and scope boundaries.",
    ["SVG", "PNG", "JSON"],
    "Contains network topology and identifiers.",
  ),
  deliverable(
    "osi_application_stack_map",
    "OSI and application-stack map",
    "Show observed transport, session, presentation, and application layers without filling unknowns.",
    ["HTML", "Markdown", "JSON"],
    "Contains product and version inventory.",
  ),
  deliverable(
    "attack_path_visualization",
    "Attack-path visualization",
    "Explain validated and alternative authorized paths through discovered assets.",
    ["SVG", "PNG", "HTML", "JSON"],
    "May reveal offensive paths and control weaknesses.",
  ),
  deliverable(
    "engagement_timeline",
    "Engagement timeline",
    "Present meaningful mission events, decisions, recoveries, and outcomes in order.",
    ["Markdown", "HTML", "CSV", "JSON"],
    "Apply event redaction and retention policy.",
  ),
  deliverable(
    "evidence_bundle",
    "Evidence bundle",
    "Package verified evidence, provenance, hashes, and chain-of-custody records.",
    ["ZIP", "JSON"],
    "Potentially high sensitivity; enforce access and export policy.",
  ),
  deliverable(
    "web_page_screenshot_gallery",
    "Web-page screenshot gallery",
    "Review authorized page captures with endpoint and evidence relationships.",
    ["HTML", "PDF", "ZIP"],
    "Screenshots require redaction and public-provider disclosure controls.",
  ),
  deliverable(
    "cve_applicability_register",
    "CVE applicability register",
    "List authoritative CVE candidates and evidence-backed applicability classifications.",
    ["Markdown", "HTML", "CSV", "JSON"],
    "Do not present unverified banners as confirmed applicability.",
  ),
  deliverable(
    "scripts_and_documentation",
    "Scripts and script documentation",
    "Export versioned source, explanation, tests, hashes, and execution references.",
    ["ZIP", "Markdown", "JSON"],
    "Never embed credentials or unrestricted client data.",
  ),
  deliverable(
    "remediation_plan",
    "Remediation plan",
    "Prioritize evidence-linked defensive actions and verification guidance.",
    ["Markdown", "HTML", "PDF", "CSV"],
    "Tailor operational detail to the approved audience.",
  ),
  deliverable(
    "raw_technical_log_export",
    "Raw technical log export",
    "Export chronological technical records for troubleshooting and audit.",
    ["JSONL", "JSON", "CSV", "TXT"],
    "Raw logs are not evidence and require strict secret redaction.",
  ),
  deliverable(
    "obsidian_engagement_pack",
    "Obsidian engagement pack",
    "Project mission knowledge as Markdown, YAML properties, attachments, and wikilinks.",
    ["ZIP", "Markdown"],
    "Respect memory scope, forgetting, and vault disclosure policy.",
  ),
  deliverable(
    "machine_readable_export",
    "Machine-readable export",
    "Provide stable typed records for downstream analysis.",
    ["JSON", "CSV"],
    "Preserve stable IDs, versions, and sensitivity labels.",
  ),
  deliverable(
    "pdf_html_markdown_report",
    "PDF, HTML, or Markdown report",
    "Render the approved mission report in common portable formats.",
    ["PDF", "HTML", "Markdown"],
    "Report claims must remain traceable to verified evidence.",
  ),
] as const;

export function buildDeliverableRegistry(
  projection: RuntimeCapabilityProjection,
): DeliverableRegistry {
  const deliverables = Object.fromEntries(
    DELIVERABLE_DEFINITIONS.map((definition) => [
      definition.id,
      { ...definition, capability: projection.deliverables[definition.id] },
    ]),
  ) as Record<DeliverableId, RegisteredDeliverable>;
  return { deliverables };
}

if (DELIVERABLE_DEFINITIONS.length !== DELIVERABLE_IDS.length) {
  throw new Error("Every canonical deliverable must have exactly one definition.");
}
