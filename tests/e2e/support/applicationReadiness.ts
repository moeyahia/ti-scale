import { expect, type Page } from "./playwright";

/**
 * Wait for the document-owned startup boundary to release the real
 * application before auditing or activating it.
 *
 * Playwright considers an opacity-zero descendant visible, while axe correctly
 * excludes an aria-hidden/inert subtree. Waiting only for a route heading can
 * therefore produce a false-green scan of the startup status instead of the
 * requested application surface.
 */
export async function waitForInteractiveApplication(page: Page): Promise<void> {
  const boundary = page.locator("[data-ti-boot-boundary='startup']");
  const application = boundary.locator(".ti-boot-boundary__application");

  await expect(boundary).toHaveAttribute("data-ti-boot-readiness", "ready");
  await expect(boundary).toHaveAttribute("data-ti-boot-phase", "complete");
  await expect(boundary).toHaveAttribute("aria-busy", "false");
  await expect(application).not.toHaveAttribute("inert", /.*/u);
  await expect(application).not.toHaveAttribute("disabled", /.*/u);
  await expect(application).not.toHaveAttribute("aria-hidden", /.*/u);
}
