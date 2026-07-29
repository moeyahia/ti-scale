interface ActiveReleaseLock {
  readonly descriptor: number;
  readonly ownerNonce: string;
}

let activeLock: ActiveReleaseLock | undefined;

/**
 * Registers the process-wide release lock descriptor for bounded child-command
 * inheritance. A child guardian receives a dup of this descriptor, keeping the
 * kernel flock alive even if the release parent is killed with SIGKILL.
 */
export function registerActiveReleaseLockDescriptor(
  descriptor: number,
  ownerNonce: string,
): () => void {
  if (!Number.isSafeInteger(descriptor) || descriptor < 0) {
    throw new Error("Active release lock descriptor is invalid");
  }
  if (!/^[0-9a-f-]{36}$/iu.test(ownerNonce)) {
    throw new Error("Active release lock owner nonce is invalid");
  }
  if (activeLock !== undefined) {
    throw new Error("An active release lock descriptor is already registered");
  }
  activeLock = Object.freeze({ descriptor, ownerNonce });
  let cleared = false;
  return () => {
    if (cleared) return;
    cleared = true;
    if (activeLock?.descriptor !== descriptor || activeLock.ownerNonce !== ownerNonce) {
      throw new Error("Active release lock descriptor ownership changed unexpectedly");
    }
    activeLock = undefined;
  };
}

export function currentActiveReleaseLockDescriptor(): number | undefined {
  return activeLock?.descriptor;
}

export function currentActiveReleaseLockOwnerNonce(): string | undefined {
  return activeLock?.ownerNonce;
}
