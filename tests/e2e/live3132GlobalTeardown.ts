import { rmSync } from "node:fs";
import {
  E2E_AUTH_STATE,
  assertManagedE2EFixturePath,
} from "./support/environment";

/** Remove the disposable browser session without touching live product data. */
export default function live3132GlobalTeardown(): void {
  assertManagedE2EFixturePath(
    E2E_AUTH_STATE,
    "The live Ti-Scale authentication state",
  );
  rmSync(E2E_AUTH_STATE, { force: true });
}
