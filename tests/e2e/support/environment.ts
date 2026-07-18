import { resolve } from "node:path";

export const E2E_RUN_ID = process.env.TI_SCALE_E2E_RUN_ID
  ?? `${process.pid}-${Date.now()}`;

// Playwright config, web servers, global setup, and worker processes inherit
// this exact path. A unique database per invocation prevents previous real
// E2E missions from changing control counts or fixture outcomes.
process.env.TI_SCALE_E2E_RUN_ID ??= E2E_RUN_ID;
process.env.TI_SCALE_E2E_DATABASE_PATH ??= resolve(
  "/tmp/ti-scale-e2e-data",
  `ti-scale-${E2E_RUN_ID}.sqlite`,
);

export const E2E_OPERATOR_TOKEN = process.env.TI_SCALE_E2E_OPERATOR_TOKEN
  ?? "ti-scale-e2e-local-operator-token-2026";
export const E2E_API_URL = process.env.TI_SCALE_E2E_API_URL ?? "http://127.0.0.1:43141";
export const E2E_AUTH_STATE = process.env.TI_SCALE_E2E_AUTH_STATE
  ?? resolve(
    "/tmp/ti-scale-e2e-data",
    `auth-state-${E2E_RUN_ID}.json`,
  );
export const E2E_DATABASE_PATH = process.env.TI_SCALE_E2E_DATABASE_PATH;
export const E2E_VAULT_ROOT = process.env.TI_SCALE_E2E_VAULT_ROOT ?? resolve(
  "/tmp/ti-scale-e2e-data",
  `vaults-${E2E_RUN_ID}`,
);
