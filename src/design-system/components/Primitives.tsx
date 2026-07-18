import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";
import { AppLink } from "../../app/router/navigation";

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

export function Card({ children, className = "", ...props }: HTMLAttributes<HTMLElement> & { children: ReactNode }) {
  return <section className={`os-card ${className}`} {...props}>{children}</section>;
}

export function Button({ variant = "primary", className = "", ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "quiet" }) {
  return <button className={`os-button os-button--${variant} ${className}`} {...props} />;
}

export function ButtonLink({ href, variant = "primary", children, className = "", "aria-label": ariaLabel }: {
  href: string;
  variant?: "primary" | "secondary" | "danger" | "quiet";
  children: ReactNode;
  className?: string;
  "aria-label"?: string;
}) {
  return <AppLink href={href} className={`os-button os-button--${variant} ${className}`} aria-label={ariaLabel}>{children}</AppLink>;
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
    <div
      className="os-progress-track"
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={normalized}
      aria-valuetext={normalized === undefined ? "Not measured" : `${normalized}% complete`}
    >
      <span style={{ width: normalized === undefined ? "0%" : `${normalized}%` }} />
    </div>
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

export function ErrorPanel({ title = "Live data is unavailable", error, onRetry }: {
  title?: string;
  error: Error;
  onRetry?: () => void;
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
        {onRetry && <Button type="button" variant="secondary" onClick={onRetry}>Try again</Button>}
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
