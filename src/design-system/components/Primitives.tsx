import { useId, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from "react";
import { AppLink } from "../../app/router/navigation";

export const titaniumPlateVariants = ["keel", "aero", "prism", "truss"] as const;
export type TitaniumPlateVariant = (typeof titaniumPlateVariants)[number];

export function resolveTitaniumPlateVariant(seed: string): TitaniumPlateVariant {
  let hash = 2_166_136_261;
  for (const character of seed) {
    hash ^= character.codePointAt(0) ?? 0;
    hash = Math.imul(hash, 16_777_619);
  }
  return titaniumPlateVariants[(hash >>> 0) % titaniumPlateVariants.length] ?? "keel";
}

export function resolveTitaniumPlateSeed({
  id,
  ariaLabel,
  className,
  fallbackId,
}: {
  readonly id?: string;
  readonly ariaLabel?: string;
  readonly className?: string;
  readonly fallbackId: string;
}): string {
  const semanticSeed = id?.trim() || ariaLabel?.trim() || className?.trim();
  return semanticSeed || `anonymous-module:${fallbackId}`;
}

type CardProps = HTMLAttributes<HTMLElement> & {
  children: ReactNode;
  plate?: TitaniumPlateVariant;
  "data-ti-plate"?: TitaniumPlateVariant;
};

export function PageHeader({ eyebrow, title, description, actions }: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="os-page-header">
      <div>
        {eyebrow && <p className="os-eyebrow">{eyebrow}</p>}
        <h1>{title}</h1>
        {description && <p className="os-page-description">{description}</p>}
      </div>
      {actions && <div className="os-page-actions">{actions}</div>}
    </header>
  );
}

export function Card({ children, className = "", plate, "data-ti-plate": requestedPlate, ...props }: CardProps) {
  const stableId = useId();
  const plateSeed = resolveTitaniumPlateSeed({
    id: props.id,
    ariaLabel: props["aria-label"],
    className,
    fallbackId: stableId,
  });
  const resolvedPlate = requestedPlate ?? plate ?? resolveTitaniumPlateVariant(plateSeed);
  return (
    <section className={`os-card ${className}`} data-ti-plate={resolvedPlate} {...props}>
      <span className="os-card__chassis" data-ti-chassis="module" aria-hidden="true">
        <i className="os-card__face" />
        <i className="os-card__facet os-card__facet--leading" />
        <i className="os-card__facet os-card__facet--trailing" />
        <i className="os-card__fastener" />
        <i className="os-card__specular-seam" />
      </span>
      {children}
    </section>
  );
}

export function Button({ variant = "primary", className = "", children, ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "quiet" }) {
  return (
    <button className={`os-button os-button--${variant} ${className}`} data-ti-actuator={variant} {...props}>
      <span className="os-button__label">{children}</span>
      <span className="os-button__mechanism" aria-hidden="true"><i /><i /><i /></span>
    </button>
  );
}

export function ButtonLink({
  href,
  variant = "primary",
  children,
  className = "",
  id,
  "aria-label": ariaLabel,
  "data-testid": dataTestId,
  "data-control-id": dataControlId,
}: {
  href: string;
  variant?: "primary" | "secondary" | "danger" | "quiet";
  children: ReactNode;
  className?: string;
  id?: string;
  "aria-label"?: string;
  "data-testid"?: string;
  "data-control-id"?: string;
}) {
  return (
    <AppLink
      href={href}
      className={`os-button os-button--${variant} ${className}`}
      id={id}
      aria-label={ariaLabel}
      data-testid={dataTestId}
      data-control-id={dataControlId}
    >
      <span className="os-button__label">{children}</span>
      <span className="os-button__mechanism" aria-hidden="true"><i /><i /><i /></span>
    </AppLink>
  );
}

export function StatusPill({ status, children }: { status: string; children?: ReactNode }) {
  const normalized = status.toLowerCase().replace(/[^a-z]+/g, "-");
  return <span className={`os-status os-status--${normalized}`}><span aria-hidden="true" />{children ?? status}</span>;
}

export function ProgressBar({ label, value }: { label: string; value: number | null | undefined }) {
  const normalized = value === null || value === undefined
    ? undefined
    : Math.min(100, Math.max(0, Math.round(value * 100)));
  return (
    <progress
      className="os-progress-track"
      aria-label={label}
      aria-valuetext={normalized === undefined ? "Not measured" : `${normalized}% complete`}
      max="100"
      value={normalized}
    />
  );
}

export function LoadingPanel({ label = "Loading current system state" }: { label?: string }) {
  return (
    <div className="os-state-panel" role="status" aria-live="polite">
      <span className="os-progress-mark" aria-hidden="true" />
      <div><strong>{label}</strong><p>Waiting for the Ti-Scale service to respond.</p></div>
    </div>
  );
}

export function ErrorPanel({
  title = "Live data is unavailable",
  error,
  onRetry,
  retryControlId,
  retryLabel = "Try again",
}: {
  title?: string;
  error: Error;
  onRetry?: () => void;
  retryControlId?: string;
  retryLabel?: string;
}) {
  const details = error as Error & { humanMessage?: string; remediation?: string; traceId?: string };
  return (
    <div className="os-state-panel os-state-panel--error" role="alert">
      <div className="os-state-symbol" aria-hidden="true">!</div>
      <div>
        <strong>{title}</strong>
        <p>{details.humanMessage ?? error.message}</p>
        {details.remediation && <p className="os-state-remediation">{details.remediation}</p>}
        {details.traceId && <p className="os-mono">Trace {details.traceId}</p>}
        {onRetry && <Button
          type="button"
          variant="secondary"
          id={retryControlId}
          data-testid={retryControlId}
          data-control-id={retryControlId}
          aria-label={retryLabel}
          onClick={onRetry}
        >Try again</Button>}
      </div>
    </div>
  );
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return (
    <div className="os-empty">
      <div className="os-empty-mark" aria-hidden="true" />
      <strong>{title}</strong>
      <p>{description}</p>
      {action}
    </div>
  );
}
