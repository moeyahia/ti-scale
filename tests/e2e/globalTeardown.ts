import { disposeManagedE2EStaticBuilds } from "../../server/static-release";
import {
  E2E_RUN_ID,
  disposeManagedE2EInvocation,
} from "./support/environment";

export default function globalTeardown(): void {
  disposeManagedE2EStaticBuilds(E2E_RUN_ID);
  disposeManagedE2EInvocation();
}
