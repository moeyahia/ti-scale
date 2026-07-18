import { ButtonLink, PageHeader, StatusPill } from "../../design-system/components/Primitives";
import { JourneyAmbient } from "../../design-system/components/BrandMedia";

export default function JourneySelectionPage() {
  return (
    <div className="os-page os-narrow-page os-journey-selection-page">
      <JourneyAmbient />
      <PageHeader eyebrow="New mission" title="Choose how you want to work" description="There are exactly two mission journeys. You can inspect providers and tools later without turning them into execution modes." />
      <section className="os-journey-grid os-journey-grid--selection" aria-label="Mission journey">
        <article className="os-journey-card os-journey-card--autonomous">
          <div className="os-journey-index" aria-hidden="true">01</div>
          <div className="os-journey-content">
            <p className="os-eyebrow">Autonomous</p><h2>Outcome first</h2>
            <p>Sign a complete operating contract, then let the runtime plan, delegate, execute, recover, validate, and report inside it. Out-of-contract work safe-stops.</p>
            <ul className="os-feature-list"><li>No routine mid-run prompts</li><li>Bounded retries, replans, time, cost, and concurrency</li><li>Permitted confirmed memory and verified lessons only</li></ul>
            <StatusPill status="contract required" />
            <ButtonLink href="/missions/new/autonomous">Go Autonomous</ButtonLink>
          </div>
        </article>
        <article className="os-journey-card os-journey-card--guided">
          <div className="os-journey-index" aria-hidden="true">02</div>
          <div className="os-journey-content">
            <p className="os-eyebrow">Guided</p><h2>Learn every step</h2>
            <p>Work collaboratively through explain, recommend, choose, observe, interpret, record, and advance. Every consequential action remains deliberate.</p>
            <ul className="os-feature-list"><li>One clear next step at a time</li><li>Manual or exact single-step execution</li><li>Durable evidence and checkpoint state</li></ul>
            <StatusPill status="operator directed" />
            <ButtonLink href="/missions/new/guided" variant="secondary">Start Guided Mission</ButtonLink>
          </div>
        </article>
      </section>
    </div>
  );
}
