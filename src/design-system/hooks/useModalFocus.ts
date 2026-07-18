import {
  type KeyboardEvent as ReactKeyboardEvent,
  type RefObject,
  useCallback,
  useEffect,
  useRef,
} from "react";

const FOCUSABLE_SELECTOR = [
  "button:not([disabled])",
  "input:not([disabled])",
  "textarea:not([disabled])",
  "select:not([disabled])",
  "a[href]",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

function focusableElements(root: HTMLElement): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)]
    .filter((element) => !element.hidden && element.getAttribute("aria-hidden") !== "true");
}

/**
 * Provides focus entry, Tab containment, Escape handling, and focus return for
 * a modal surface without coupling those accessibility rules to page state.
 */
export function useModalFocus<T extends HTMLElement>(
  active: boolean,
  onClose: () => void,
  closeDisabled = false,
): {
  readonly dialogRef: RefObject<T | null>;
  readonly onDialogKeyDown: (event: ReactKeyboardEvent<T>) => void;
} {
  const dialogRef = useRef<T>(null);
  const closeRef = useRef(onClose);
  const closeDisabledRef = useRef(closeDisabled);
  closeRef.current = onClose;
  closeDisabledRef.current = closeDisabled;

  useEffect(() => {
    if (!active) return undefined;
    const returnFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const frame = requestAnimationFrame(() => {
      const dialog = dialogRef.current;
      if (!dialog) return;
      const preferred = dialog.querySelector<HTMLElement>("[data-modal-initial-focus]");
      (preferred ?? focusableElements(dialog)[0] ?? dialog).focus();
    });
    return () => {
      cancelAnimationFrame(frame);
      if (returnFocus?.isConnected) returnFocus.focus();
    };
  }, [active]);

  const onDialogKeyDown = useCallback((event: ReactKeyboardEvent<T>): void => {
    if (event.key === "Escape") {
      if (closeDisabledRef.current) return;
      event.preventDefault();
      event.stopPropagation();
      closeRef.current();
      return;
    }
    if (event.key !== "Tab") return;
    const dialog = dialogRef.current;
    if (!dialog) return;
    const focusable = focusableElements(dialog);
    if (focusable.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = focusable[0]!;
    const last = focusable.at(-1)!;
    if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }, []);

  return { dialogRef, onDialogKeyDown };
}
