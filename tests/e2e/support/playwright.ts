import { expect, test as base } from "@playwright/test";
import {
  BrowserAuditSession,
  installBrowserAuditRuntimeInstrumentation,
  type BrowserAuditController,
  type BrowserAuditOptions,
} from "./browserAudit";
import {
  createInteractionActivationRecorder,
  type InteractionActivationRecorder,
} from "./interactionActivationFixture";

interface AutomaticAuditFixtures {
  readonly browserAudit: BrowserAuditController;
  readonly interactionActivation: InteractionActivationRecorder;
}

export interface AuditedIsolatedBrowserContext {
  readonly context: import("@playwright/test").BrowserContext;
  readonly browserAudit: BrowserAuditController;
  readonly createPage: () => Promise<import("@playwright/test").Page>;
}

export interface AuditedIsolatedBrowserContextOptions {
  readonly context?: import("@playwright/test").BrowserContextOptions;
  readonly audit?: BrowserAuditOptions;
}

/**
 * Owns the complete lifecycle for an additional browser context.
 *
 * Performance tests need a genuinely fresh context for every cold-navigation
 * sample. They must not bypass the same console, page-error, request, response,
 * EventSource, and teardown audit used by the default Playwright fixtures.
 * Keeping context creation and disposal here makes that boundary structural:
 * specifications receive an already-instrumented context and cannot finalize
 * or dispose its audit session themselves.
 */
export async function withAuditedIsolatedBrowserContext<T>(
  browser: import("@playwright/test").Browser,
  testInfo: import("@playwright/test").TestInfo,
  options: AuditedIsolatedBrowserContextOptions,
  use: (scope: AuditedIsolatedBrowserContext) => Promise<T>,
): Promise<T> {
  const context = await browser.newContext(options.context);
  await installBrowserAuditRuntimeInstrumentation(context);
  const session = BrowserAuditSession.forContext(context, options.audit);
  const createPage = async (): Promise<import("@playwright/test").Page> => {
    const page = await context.newPage();
    session.attach(page);
    return page;
  };

  let result: T | undefined;
  let operationError: unknown;
  try {
    result = await use({ context, browserAudit: session, createPage });
  } catch (error) {
    operationError = error;
  }

  const lifecycleErrors: unknown[] = [];
  for (const page of context.pages()) {
    try {
      await session.closeAuditedPage(page);
    } catch (error) {
      lifecycleErrors.push(error);
    }
  }
  try {
    await session.finalize(testInfo);
  } catch (error) {
    lifecycleErrors.push(error);
  } finally {
    session.dispose();
    try {
      await context.close();
    } catch (error) {
      lifecycleErrors.push(error);
    }
  }

  const failures = [
    ...(operationError === undefined ? [] : [operationError]),
    ...lifecycleErrors,
  ];
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw new AggregateError(
      failures,
      "The isolated browser operation and its mandatory audit lifecycle failed",
    );
  }
  return result as T;
}

/**
 * The only Playwright test object permitted in V2 browser specifications.
 * The audit session exists before the first page, attaches every popup, and
 * finalizes after the primary page closes so teardown failures cannot escape.
 */
export const test = base.extend<AutomaticAuditFixtures>({
  interactionActivation: async ({}, use, testInfo) => {
    const activation = createInteractionActivationRecorder(testInfo);
    try {
      await use(activation.recorder);
    } finally {
      await activation.attach();
    }
  },
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
  Browser,
  BrowserContext,
  BrowserContextOptions,
  CDPSession,
  ConsoleMessage,
  Download,
  Locator,
  Page,
  Request,
  Response,
  Route,
  TestInfo,
} from "@playwright/test";
