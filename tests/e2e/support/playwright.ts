import { expect, test as base } from "@playwright/test";
import {
  BrowserAuditSession,
  installBrowserAuditRuntimeInstrumentation,
  type BrowserAuditController,
} from "./browserAudit";

interface AutomaticAuditFixtures {
  readonly browserAudit: BrowserAuditController;
}

/**
 * The only Playwright test object permitted in V2 browser specifications.
 * The audit session exists before the first page, attaches every popup, and
 * finalizes after the primary page closes so teardown failures cannot escape.
 */
export const test = base.extend<AutomaticAuditFixtures>({
  browserAudit: [async ({ context }, use, testInfo) => {
    await installBrowserAuditRuntimeInstrumentation(context);
    const session = BrowserAuditSession.forContext(context, {
      allowEventStreamNavigationAbort: true,
    });
    try {
      await use(session);
    } finally {
      try {
        await session.finalize(testInfo);
      } finally {
        session.dispose();
      }
    }
  }, { auto: true }],
  page: async ({ context, browserAudit }, use) => {
    void browserAudit;
    const lifecycle = BrowserAuditSession.forContext(context);
    const page = await context.newPage();
    lifecycle.attach(page);
    try {
      await use(page);
    } finally {
      await lifecycle.closeAuditedPage(page);
    }
  },
});

export { expect };
export type {
  APIResponse,
  ConsoleMessage,
  Download,
  Locator,
  Page,
  Request,
  Response,
  Route,
  TestInfo,
} from "@playwright/test";
