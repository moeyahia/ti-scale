import { AppLink, useNavigation } from "../../app/router/navigation";
import type { ReactNode } from "react";
import { assetUrl } from "../../lib/assetUrl";

const items = [
  { href: "/brain", label: "Home" },
  { href: "/brain/graph", label: "Graph" },
  { href: "/brain/inbox", label: "Memory Inbox" },
  { href: "/brain/control", label: "Controls" },
  { href: "/brain/vault", label: "Obsidian Vault" },
] as const;

export function BrainNav() {
  const { pathname } = useNavigation();
  return (
    <nav className="brain-tabs" aria-label="Second Brain">
      {items.map((item) => {
        const active = item.href === "/brain" ? pathname === item.href : pathname.startsWith(item.href);
        return <AppLink key={item.href} href={item.href} className={active ? "is-active" : ""} aria-current={active ? "page" : undefined}>{item.label}</AppLink>;
      })}
    </nav>
  );
}

export function BrainEmpty({ kind = "brain", title, description, action }: {
  kind?: "brain" | "vault";
  title: string;
  description: string;
  action?: ReactNode;
}) {
  const imageAvif = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-640.avif");
  const imageWebp = assetUrl("brand-v2/optimized/ti-scale-higgsfield-core-640.webp");
  return (
    <div className="brain-empty">
      <picture aria-hidden="true">
        <source srcSet={imageAvif} type="image/avif" />
        <img src={imageWebp} width="640" height="366" alt="" loading="lazy" />
      </picture>
      <div><strong>{title}</strong><p>{description}</p>{action}</div>
    </div>
  );
}

export function formatBrainDate(value?: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Invalid timestamp" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function scopeLabel(scope: { kind: string; engagementId?: string; missionId?: string }): string {
  if (scope.kind === "mission") return `Mission · ${scope.missionId ?? "unknown"}`;
  if (scope.kind === "engagement") return `Engagement · ${scope.engagementId ?? "unknown"}`;
  return "Global";
}
