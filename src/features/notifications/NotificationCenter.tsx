import { useCallback, useEffect, useRef, useState, type RefObject } from "react";
import { AppLink } from "../../app/router/navigation";
import {
  fetchNotifications,
  fetchNotificationUnreadCount,
  markAllNotificationsRead,
  markNotificationRead,
} from "../../data/api/notifications";
import { useQuery, useQueryCache } from "../../data/cache/QueryProvider";
import type { InAppNotification } from "../../domain/types/notifications";

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium", timeStyle: "short",
  }).format(date);
}

export function NotificationPanel({
  items,
  unreadCount,
  loading = false,
  busy = false,
  hasMore = false,
  loadingMore = false,
  loadMoreError,
  onMarkRead,
  onMarkAllRead,
  onLoadMore,
  onClose,
  initialFocusRef,
}: {
  items: readonly InAppNotification[];
  unreadCount: number;
  loading?: boolean;
  busy?: boolean;
  hasMore?: boolean;
  loadingMore?: boolean;
  loadMoreError?: string;
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
  onLoadMore?: () => void;
  onClose: () => void;
  initialFocusRef?: RefObject<HTMLButtonElement | null>;
}) {
  return (
    <section className="os-notification-panel" role="dialog" aria-label="In-app notifications" aria-modal="false">
      <header>
        <div><strong>Notifications</strong><span>{unreadCount} unread</span></div>
        <button ref={initialFocusRef} type="button" className="os-icon-button" aria-label="Close notifications" onClick={onClose}>
          <svg aria-hidden="true" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18" /></svg>
        </button>
      </header>
      {unreadCount > 0 && (
        <button type="button" className="os-notification-read-all" disabled={busy} onClick={onMarkAllRead}>
          Mark all as read
        </button>
      )}
      {loading ? (
        <p className="os-notification-state" role="status">Loading current notifications…</p>
      ) : items.length === 0 ? (
        <p className="os-notification-state">No in-app notifications. Actionable mission events will appear here.</p>
      ) : (
        <>
          <ul className="os-notification-list">
            {items.map((item) => (
              <li key={item.id} className={item.readAt ? "is-read" : "is-unread"}>
                <span className={`os-notification-severity os-notification-severity--${item.severity}`} aria-hidden="true" />
                <AppLink href={item.deepLink} onClick={() => { if (!item.readAt) onMarkRead(item.id); onClose(); }}>
                  <strong>{item.title}</strong>
                  <p>{item.body}</p>
                  <span>{item.mission.name} · {item.run.journey === "autonomous" ? "Autonomous" : "Guided"}</span>
                  <time dateTime={item.createdAt}>{formatTime(item.createdAt)}</time>
                </AppLink>
                {!item.readAt && (
                  <button type="button" disabled={busy} onClick={() => onMarkRead(item.id)} aria-label={`Mark ${item.title} as read`}>
                    Mark read
                  </button>
                )}
              </li>
            ))}
          </ul>
          {hasMore && onLoadMore && (
            <button
              type="button"
              className="os-notification-load-more"
              disabled={loadingMore}
              onClick={onLoadMore}
            >
              {loadingMore ? "Loading older notifications…" : "Load older notifications"}
            </button>
          )}
          {loadMoreError && <p className="os-notification-page-error" role="alert">{loadMoreError}</p>}
        </>
      )}
      <p className="os-notification-channel">In-app delivery only. No email, SMS, or webhook is configured.</p>
    </section>
  );
}

export function NotificationCenter() {
  const cache = useQueryCache();
  const notifications = useQuery(
    "notifications:recent",
    (signal) => fetchNotifications(signal, { limit: 20 }),
    { staleTime: 30_000 },
  );
  const unread = useQuery("notifications:unread", fetchNotificationUnreadCount, { staleTime: 30_000 });
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [mutationError, setMutationError] = useState<string>();
  const [olderItems, setOlderItems] = useState<readonly InAppNotification[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null | undefined>(undefined);
  const [loadingMore, setLoadingMore] = useState(false);
  const [loadMoreError, setLoadMoreError] = useState<string>();
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const loadMoreController = useRef<AbortController | undefined>(undefined);

  const refresh = () => {
    cache.invalidate("notifications:recent");
    cache.invalidate("notifications:unread");
  };

  const closePanel = useCallback(() => {
    setOpen(false);
    const restore = () => trigger.current?.focus();
    if (typeof window !== "undefined" && typeof window.requestAnimationFrame === "function") {
      window.requestAnimationFrame(restore);
    } else {
      setTimeout(restore, 0);
    }
  }, []);

  useEffect(() => {
    setOlderItems([]);
    setNextCursor(undefined);
    setLoadMoreError(undefined);
  }, [notifications.data]);

  useEffect(() => () => loadMoreController.current?.abort(), []);

  useEffect(() => {
    if (!open) return;
    const focusFrame = window.requestAnimationFrame(() => closeButton.current?.focus());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closePanel();
      }
    };
    const onPointerDown = (event: MouseEvent) => {
      if (root.current && event.target instanceof Node && !root.current.contains(event.target)) closePanel();
    };
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("mousedown", onPointerDown);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("mousedown", onPointerDown);
    };
  }, [closePanel, open]);

  const cursorForNextPage = nextCursor === undefined
    ? notifications.data?.nextCursor ?? null
    : nextCursor;

  const loadMore = async () => {
    if (!cursorForNextPage || loadingMore) return;
    loadMoreController.current?.abort();
    const controller = new AbortController();
    loadMoreController.current = controller;
    setLoadingMore(true);
    setLoadMoreError(undefined);
    try {
      const page = await fetchNotifications(controller.signal, { limit: 20, cursor: cursorForNextPage });
      setOlderItems((current) => {
        const seen = new Set(current.map((item) => item.id));
        return [...current, ...page.items.filter((item) => !seen.has(item.id))];
      });
      setNextCursor(page.nextCursor);
    } catch (error) {
      const aborted = error instanceof DOMException && error.name === "AbortError";
      if (!aborted) setLoadMoreError(error instanceof Error ? error.message : "Older notifications could not be loaded");
    } finally {
      if (loadMoreController.current === controller) {
        loadMoreController.current = undefined;
        setLoadingMore(false);
      }
    }
  };

  const mutate = async (operation: () => Promise<unknown>) => {
    if (busy) return;
    setBusy(true);
    setMutationError(undefined);
    try {
      await operation();
      setOlderItems([]);
      setNextCursor(undefined);
      refresh();
    } catch (error) {
      setMutationError(error instanceof Error ? error.message : "Notification update failed");
    } finally {
      setBusy(false);
    }
  };

  const unreadCount = unread.data?.unreadCount ?? 0;
  const displayedItems = (() => {
    const seen = new Set<string>();
    return [...(notifications.data?.items ?? []), ...olderItems].filter((item) => {
      if (seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    });
  })();
  return (
    <div className="os-notification-center" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="os-icon-button os-notification-trigger"
        aria-label={`Notifications, ${unreadCount} unread`}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => { if (open) closePanel(); else setOpen(true); }}
      >
        <svg aria-hidden="true" viewBox="0 0 24 24"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4" /></svg>
        {unreadCount > 0 && <span className="os-notification-badge" aria-hidden="true">{Math.min(unreadCount, 99)}</span>}
      </button>
      <span className="os-visually-hidden" role="status" aria-live="polite">{unreadCount} unread in-app notifications</span>
      {open && (
        <NotificationPanel
          items={displayedItems}
          unreadCount={unreadCount}
          loading={notifications.isLoading}
          busy={busy}
          hasMore={cursorForNextPage !== null}
          loadingMore={loadingMore}
          loadMoreError={loadMoreError}
          onMarkRead={(id) => { void mutate(() => markNotificationRead(id)); }}
          onMarkAllRead={() => { void mutate(markAllNotificationsRead); }}
          onLoadMore={() => { void loadMore(); }}
          onClose={closePanel}
          initialFocusRef={closeButton}
        />
      )}
      {mutationError && <p className="os-visually-hidden" role="alert">{mutationError}</p>}
    </div>
  );
}
