import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import {
  BOOT_SEQUENCE_TIMING,
  BootSequence,
  bootPhaseLabel,
  formatBootElapsed,
} from "../../../src/app/boot/BootSequence";
import {
  PARTICLE_BOOT_COUNT,
  PARTICLE_BOOT_GROUPS,
  ParticleBootMark,
} from "../../../src/app/boot/ParticleBootMark";

const bootSource = readFileSync(new URL("../../../src/app/boot/BootSequence.tsx", import.meta.url), "utf8");
const bootCss = readFileSync(new URL("../../../src/app/boot/boot-sequence.css", import.meta.url), "utf8");
const particleSource = readFileSync(new URL("../../../src/app/boot/ParticleBootMark.tsx", import.meta.url), "utf8");
const providers = readFileSync(new URL("../../../src/app/providers/AppProviders.tsx", import.meta.url), "utf8");
const auth = readFileSync(new URL("../../../src/app/providers/AuthProvider.tsx", import.meta.url), "utf8");

describe("Ti-Scale first-load boot contract", () => {
  test("renders one accessible, image-plane-free particle startup mechanism", () => {
    const markup = renderToStaticMarkup(
      <BootSequence readiness={{
        ready: false,
        status: "Verifying protected operator session",
        next: "Command Center",
      }}>
        <button type="button">Command control</button>
      </BootSequence>,
    );

    expect(markup).toContain('data-ti-boot-boundary="startup"');
    expect(markup).toContain('data-ti-boot-sequence-count="1"');
    expect(markup).toContain('data-ti-boot-phase="orbiting"');
    expect(markup).toContain('role="status"');
    expect(markup).toContain('aria-live="polite"');
    expect(markup).toContain('<fieldset class="ti-boot-boundary__application" disabled=""');
    expect(markup).toContain('aria-hidden="true" inert=""');
    expect(markup).toContain('data-ti-boot-particle-mark="forming-core"');
    expect(markup).toContain(`data-ti-boot-particle-count="${PARTICLE_BOOT_COUNT}"`);
    expect(markup.match(/ti-boot-particle-mark__particle ti-boot-particle-mark__particle--tone-\d/gu)).toHaveLength(PARTICLE_BOOT_COUNT);
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain('style="');
  });

  test("uses deterministic titanium point geometry without adding Three or WebGL to startup", () => {
    expect(PARTICLE_BOOT_COUNT).toBe(152);
    expect(PARTICLE_BOOT_GROUPS.map((group) => group.length)).toEqual([52, 36, 40, 24]);
    const firstRender = renderToStaticMarkup(<ParticleBootMark />);
    const secondRender = renderToStaticMarkup(<ParticleBootMark />);
    expect(firstRender).toBe(secondRender);
    expect(firstRender).toContain('viewBox="0 0 360 360"');
    expect(firstRender).toContain('aria-hidden="true"');
    expect(particleSource).not.toMatch(/from ["']three["']/u);
    expect(particleSource).not.toContain("WebGLRenderer");
    expect(particleSource).not.toContain("requestAnimationFrame");
  });

  test("uses a finite sub-two-second choreography and a stable pending state", () => {
    expect(BOOT_SEQUENCE_TIMING.earliestHandoffMs + BOOT_SEQUENCE_TIMING.handoffMs).toBeLessThanOrEqual(1_250);
    expect(BOOT_SEQUENCE_TIMING.earliestHandoffMs - BOOT_SEQUENCE_TIMING.lockMs).toBeGreaterThanOrEqual(200);
    expect(BOOT_SEQUENCE_TIMING.safetyCompleteMs).toBeLessThan(2_000);
    expect(BOOT_SEQUENCE_TIMING.lockMs).toBeLessThan(BOOT_SEQUENCE_TIMING.earliestHandoffMs);
    expect(bootPhaseLabel("locked", {
      ready: false,
      status: "Verifying protected operator session",
      next: "Command Center",
    })).toContain("Startup still in progress");
    expect(formatBootElapsed(2_650)).toBe("2.6s elapsed");
    expect(bootCss).toContain("@keyframes ti-boot-particle-field-form");
    expect(bootCss).toContain("@keyframes ti-boot-particle-arrive");
    expect(bootCss).toContain("@keyframes ti-boot-core-handoff");
    expect(bootCss).not.toMatch(/\binfinite\b/u);
    expect(bootCss).not.toContain("url(");
  });

  test("composites directly into the app canvas and hands to one real core without an opacity dip", () => {
    expect(bootCss).toContain("background: var(--ti-boot-canvas);");
    expect(bootCss).toContain("@keyframes ti-boot-real-core-receive");
    expect(bootCss).toContain('.ti-boot-sequence[data-ti-boot-phase="handoff"]');
    expect(bootCss).toContain("background: transparent;");
    expect(bootCss).toContain('0%, 60% { opacity: 0; }');
    expect(bootCss).toContain('100% { opacity: 1; }');
    expect(bootCss).not.toContain("@keyframes ti-boot-application-receive");
    expect(bootCss).not.toContain("@keyframes ti-boot-canvas-handoff");
    expect(bootCss).not.toContain("will-change");
    expect(bootCss).not.toContain("mix-blend-mode");
    expect(bootCss).not.toMatch(/\bfilter\s*:/u);
    expect(bootCss).not.toContain("ti-boot-panel");
    expect(providers.match(/<BootSequence\b/gu)).toHaveLength(1);
    expect(providers.indexOf("<BootSequence")).toBeLessThan(providers.indexOf("<AuthProvider"));
  });

  test("settles hidden and reduced-motion documents and cannot replay for routing", () => {
    expect(bootSource).toContain('document.addEventListener("visibilitychange"');
    expect(bootSource).toContain('window.matchMedia(REDUCED_MOTION_QUERY)');
    expect(bootSource).not.toContain("sessionStorage");
    expect(bootSource).not.toContain("localStorage");
    expect(bootCss).toContain('@media (prefers-reduced-motion: reduce)');
    expect(bootCss).toContain('.ti-boot-sequence[data-document-hidden="true"] .ti-boot-particle-mark__particle');
    expect(bootCss).toContain("animation: none !important;");
    expect(providers).not.toContain("useNavigation");
    expect(auth).toContain("initialRefreshStartedRef.current");
    expect(auth).toContain("mount exactly once");
    expect(bootSource).toContain("BOOT_PHASE_ORDER");
    expect(bootSource).toContain('BOOT_PHASE_ORDER[next] <= BOOT_PHASE_ORDER[phaseRef.current]');
    expect(bootSource).toContain('phaseRef.current === "locked"');
    expect(bootSource).toContain("hidden={!blocking}");
    expect(bootCss).toContain(".ti-boot-sequence[hidden]");
    expect(bootSource).toContain("safetyCompleteMs");
    expect(auth).toContain("AUTH_STARTUP_DELAY_NOTICE_MS = 3_000");
    expect(auth).toContain("AUTH_STARTUP_TIMEOUT_MS = 8_000");
    expect(auth).toContain("Session service response delayed · Connection remains pending");
    expect(auth).toContain("Authentication recovery");
  });
});
