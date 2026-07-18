import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

interface CacheEntry<T = unknown> {
  data?: T;
  error?: Error;
  updatedAt: number;
  promise?: Promise<T>;
  controller?: AbortController;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException
    ? error.name === "AbortError"
    : error instanceof Error && error.name === "AbortError";
}

export class QueryCache {
  private readonly entries = new Map<string, CacheEntry>();
  private readonly listeners = new Map<string, Set<() => void>>();
  private suspended = false;

  subscribe(key: string, listener: () => void): () => void {
    const listeners = this.listeners.get(key) ?? new Set();
    listeners.add(listener);
    this.listeners.set(key, listeners);
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) {
        this.listeners.delete(key);
        this.cancelIfUnused(key);
      }
    };
  }

  private subscribedKeys(): string[] {
    return [...new Set([...this.entries.keys(), ...this.listeners.keys()])];
  }

  private notify(key: string): void {
    this.listeners.get(key)?.forEach((listener) => listener());
  }

  read<T>(key: string): CacheEntry<T> | undefined {
    return this.entries.get(key) as CacheEntry<T> | undefined;
  }

  async fetch<T>(key: string, loader: (signal: AbortSignal) => Promise<T>, staleTime: number, force = false): Promise<T> {
    if (this.suspended) {
      // Retain a dormant key so pages restored from the back-forward cache can
      // notify the mounted subscriber and perform a fresh authoritative read.
      // Do not notify here: a mounted listener would immediately retry while
      // the document is still suspended.
      if (!this.entries.has(key)) this.entries.set(key, { updatedAt: 0 });
      throw new DOMException("Query cache is suspended while the document is inactive", "AbortError");
    }
    const current = this.read<T>(key);
    if (!force && current?.data !== undefined && Date.now() - current.updatedAt < staleTime) return current.data;
    if (current?.promise) return current.promise;
    const controller = new AbortController();
    const promise = Promise.resolve().then(() => {
      // pagehide can occur between fetch() and this microtask. Refuse to invoke
      // the loader after lifecycle suspension so a lazy effect cannot create a
      // new network request while the document is already being discarded.
      if (this.suspended || controller.signal.aborted) {
        throw new DOMException("Query cache is suspended while the document is inactive", "AbortError");
      }
      return loader(controller.signal);
    });
    this.entries.set(key, { ...current, promise, controller, updatedAt: current?.updatedAt ?? 0 });
    this.notify(key);
    try {
      const data = await promise;
      // An aborted/stale request must never overwrite a replacement request.
      if (this.read<T>(key)?.promise === promise) {
        this.entries.set(key, { data, updatedAt: Date.now() });
        this.notify(key);
      }
      return data;
    } catch (error) {
      if (this.read<T>(key)?.promise === promise) {
        this.entries.set(key, isAbortError(error) || controller.signal.aborted
          ? {
              data: current?.data,
              error: current?.error,
              updatedAt: current?.updatedAt ?? 0,
            }
          : {
              data: current?.data,
              error: error instanceof Error ? error : new Error("Query failed"),
              // A failed event-driven refresh must not become a render/retry loop.
              // The caller can retry explicitly or on the next invalidation.
              updatedAt: Date.now(),
            });
        this.notify(key);
      }
      throw error;
    }
  }

  cancelIfUnused(key: string): void {
    if ((this.listeners.get(key)?.size ?? 0) > 0) return;
    const current = this.entries.get(key);
    if (!current?.promise || !current.controller) return;
    current.controller.abort();
    this.entries.set(key, {
      data: current.data,
      error: current.error,
      updatedAt: current.updatedAt,
    });
  }

  /**
   * Abort every mounted read before a document is discarded. WebKit can
   * otherwise surface navigation-cancelled same-origin fetches as global
   * "access control checks" page errors even though each query promise has a
   * local rejection handler. Clearing the promise identity first also keeps a
   * late response from overwriting the next document's authoritative state.
   */
  cancelAll(): void {
    for (const [key, current] of this.entries) {
      if (!current.promise || !current.controller) continue;
      current.controller.abort("Ti-Scale document is leaving");
      this.entries.set(key, {
        data: current.data,
        error: current.error,
        updatedAt: current.updatedAt,
      });
    }
  }

  suspend(): void {
    this.suspended = true;
    this.cancelAll();
  }

  resume(): void {
    if (!this.suspended) return;
    this.suspended = false;
    // A BFCache restore keeps this QueryCache and its mounted subscribers.
    // Mark only those visible keys stale so their existing listener performs
    // one bounded authoritative refresh. A normal navigation creates a fresh
    // provider and never reaches this path.
    this.invalidateSubscribed();
  }

  invalidate(key: string): void {
    const current = this.entries.get(key);
    if (current) this.entries.set(key, { ...current, updatedAt: 0 });
    this.notify(key);
  }

  invalidatePrefix(prefix: string): void {
    this.subscribedKeys()
      .filter((key) => key.startsWith(prefix))
      .forEach((key) => this.invalidate(key));
  }

  /**
   * Reconcile only mounted authoritative queries. This is intentionally not a
   * full-cache invalidation: one bounded fallback tick causes at most one
   * request per visible query key and existing in-flight requests stay deduped.
   */
  invalidateSubscribed(): void {
    [...this.listeners.keys()].forEach((key) => this.invalidate(key));
  }

  /**
   * Establish a post-mutation read boundary. A pre-mutation request may still
   * be in flight, so let its exact promise settle and then force a second read
   * that owns the canonical cache value returned to the mutation surface.
   */
  async reconcile<T>(key: string, loader: (signal: AbortSignal) => Promise<T>, staleTime: number): Promise<T> {
    await this.read<T>(key)?.promise?.catch(() => undefined);
    return this.fetch(key, loader, staleTime, true);
  }
}

const QueryContext = createContext<QueryCache | null>(null);

export function QueryProvider({ children }: { children: ReactNode }) {
  const cache = useMemo(() => new QueryCache(), []);
  useEffect(() => {
    // React Strict Mode intentionally performs a setup -> cleanup -> setup
    // cycle in development. The simulated cleanup suspends the cache just as a
    // real pagehide would, so every setup must explicitly reactivate it. A
    // genuine BFCache restore remains covered by the pageshow listener below.
    cache.resume();
    const suspendDocumentReads = () => { cache.suspend(); };
    const resumeDocumentReads = () => { cache.resume(); };
    window.addEventListener("pagehide", suspendDocumentReads, { capture: true });
    window.addEventListener("pageshow", resumeDocumentReads, { capture: true });
    return () => {
      window.removeEventListener("pagehide", suspendDocumentReads, { capture: true });
      window.removeEventListener("pageshow", resumeDocumentReads, { capture: true });
      cache.suspend();
    };
  }, [cache]);
  return <QueryContext.Provider value={cache}>{children}</QueryContext.Provider>;
}

export function useQueryCache(): QueryCache {
  const cache = useContext(QueryContext);
  if (!cache) throw new Error("useQueryCache must be used inside QueryProvider");
  return cache;
}

export interface QueryResult<T> {
  data?: T;
  error?: Error;
  isLoading: boolean;
  isRefreshing: boolean;
  refresh: () => void;
  /**
   * Wait for any older read to settle, then fetch a new canonical snapshot.
   * Mutation surfaces use this to avoid accepting an in-flight pre-mutation
   * response as their reconciliation read.
   */
  reconcile: () => Promise<void>;
}

export function useQuery<T>(
  key: string,
  loader: (signal: AbortSignal) => Promise<T>,
  options: { staleTime?: number } = {},
): QueryResult<T> {
  const cache = useQueryCache();
  const staleTime = options.staleTime ?? 15_000;
  const [, render] = useState(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const run = useCallback((force = false) => {
    void cache.fetch(key, (signal) => loaderRef.current(signal), staleTime, force).catch(() => undefined);
  }, [cache, key, staleTime]);

  useEffect(() => {
    const unsubscribe = cache.subscribe(key, () => {
      const current = cache.read<T>(key);
      render((value) => value + 1);
      if (current?.updatedAt === 0 && !current.promise) run(true);
    });
    run(false);
    return () => {
      unsubscribe();
    };
  }, [cache, key, run]);

  const entry = cache.read<T>(key);
  return {
    data: entry?.data,
    error: entry?.error,
    isLoading: !entry?.data && !entry?.error,
    isRefreshing: Boolean(entry?.data && entry?.promise),
    refresh: () => { run(true); },
    reconcile: async () => {
      await cache.reconcile(key, (signal) => loaderRef.current(signal), staleTime);
    },
  };
}
