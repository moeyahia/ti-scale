import {
  Children,
  Fragment,
  isValidElement,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type OptionHTMLAttributes,
  type ReactElement,
  type ReactNode,
  type SelectHTMLAttributes,
} from "react";
import { createPortal } from "react-dom";

type SelectOption = {
  readonly value: string;
  readonly label: string;
  readonly disabled: boolean;
};

/** Resolve the first enabled option matching the current accessible typeahead query. */
export function findTitaniumTypeaheadIndex(options: readonly SelectOption[], query: string): number {
  const normalizedQuery = query.toLocaleLowerCase();
  if (!normalizedQuery) return -1;
  return options.findIndex((option) => (
    !option.disabled && option.label.toLocaleLowerCase().startsWith(normalizedQuery)
  ));
}

type TitaniumSelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "multiple" | "size"> & {
  /** Visible operational state, separate from the native disabled state. */
  readonly loading?: boolean;
  /** Human-readable validation or load failure shown without replacing the field. */
  readonly error?: string;
  /** Stable interaction-manifest identity owned by the visible combobox. */
  readonly "data-control-id"?: string;
};

function textFromNode(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textFromNode).join("");
  if (!isValidElement<{ children?: ReactNode }>(node)) return "";
  return textFromNode(node.props.children);
}

function collectOptions(node: ReactNode, result: SelectOption[] = []): SelectOption[] {
  Children.forEach(node, (child) => {
    if (!isValidElement(child)) return;
    if (child.type === Fragment) {
      collectOptions((child.props as { children?: ReactNode }).children, result);
      return;
    }
    if (child.type === "option") {
      const option = child as ReactElement<OptionHTMLAttributes<HTMLOptionElement>>;
      const label = textFromNode(option.props.children).trim();
      result.push({
        value: String(option.props.value ?? label),
        label,
        disabled: Boolean(option.props.disabled),
      });
      return;
    }
    collectOptions((child.props as { children?: ReactNode }).children, result);
  });
  return result;
}

function nextEnabledOption(options: readonly SelectOption[], from: number, direction: 1 | -1): number {
  if (options.length === 0) return -1;
  for (let offset = 1; offset <= options.length; offset += 1) {
    const index = (from + (offset * direction) + options.length) % options.length;
    if (!options[index]?.disabled) return index;
  }
  return -1;
}

function boundaryEnabledOption(options: readonly SelectOption[], direction: 1 | -1): number {
  const start = direction === 1 ? 0 : options.length - 1;
  for (let index = start; index >= 0 && index < options.length; index += direction) {
    if (!options[index]?.disabled) return index;
  }
  return -1;
}

function copiedLabel(control: HTMLButtonElement | null): string | undefined {
  const label = control?.labels?.[0];
  if (!label) return undefined;
  const clone = label.cloneNode(true) as HTMLLabelElement;
  clone.querySelectorAll(".os-titanium-select, input, select, textarea, button").forEach((element) => element.remove());
  const text = clone.textContent?.replace(/\s+/gu, " ").trim();
  return text || undefined;
}

/**
 * Application-owned combobox with a canonical, inert form proxy.
 *
 * The visible trigger is never a platform select, so macOS/iOS/Windows cannot
 * substitute an operating-system picker. The hidden native element preserves
 * form payloads and existing browser automation without entering the
 * accessibility tree or keyboard order.
 */
export function TitaniumSelect({
  children,
  className = "",
  disabled = false,
  loading = false,
  error,
  onChange,
  onInvalid,
  value,
  defaultValue,
  id,
  required,
  autoFocus,
  title,
  "aria-label": ariaLabel,
  "aria-labelledby": ariaLabelledBy,
  "aria-describedby": ariaDescribedBy,
  "data-control-id": dataControlId,
  ...selectProps
}: TitaniumSelectProps) {
  const generatedId = useId().replaceAll(":", "");
  const selectId = id ?? `ti-select-${generatedId}`;
  const proxyId = `${selectId}-form-proxy`;
  const listboxId = `${selectId}-listbox`;
  const errorId = `${selectId}-error`;
  const rootRef = useRef<HTMLSpanElement>(null);
  const selectRef = useRef<HTMLSelectElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listboxRef = useRef<HTMLDivElement>(null);
  const options = useMemo(() => collectOptions(children), [children]);
  const controlled = value !== undefined;
  const [internalValue, setInternalValue] = useState(() => String(defaultValue ?? options.find((option) => !option.disabled)?.value ?? ""));
  const resolvedValue = controlled ? String(value ?? "") : internalValue;
  const selectedIndex = options.findIndex((option) => option.value === resolvedValue);
  const selectedOption = options[selectedIndex];
  const closedActiveIndex = selectedIndex >= 0
    ? selectedIndex
    : boundaryEnabledOption(options, 1);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(closedActiveIndex);
  const [derivedLabel, setDerivedLabel] = useState(ariaLabel ?? "Select");
  const typeaheadRef = useRef("");
  const typeaheadTimerRef = useRef<number | undefined>(undefined);
  const unavailable = disabled || loading;

  const resetTypeahead = () => {
    typeaheadRef.current = "";
    if (typeaheadTimerRef.current !== undefined) {
      window.clearTimeout(typeaheadTimerRef.current);
      typeaheadTimerRef.current = undefined;
    }
  };

  useLayoutEffect(() => {
    if (ariaLabel || ariaLabelledBy) return;
    setDerivedLabel(copiedLabel(triggerRef.current) ?? "Select");
  }, [ariaLabel, ariaLabelledBy, children]);

  useEffect(() => {
    if (!open && activeIndex !== closedActiveIndex) {
      setActiveIndex(closedActiveIndex);
    }
  }, [activeIndex, closedActiveIndex, open]);

  useEffect(() => {
    if (!open) return undefined;
    const closeOutside = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!rootRef.current?.contains(target) && !listboxRef.current?.contains(target)) {
        resetTypeahead();
        setOpen(false);
      }
    };
    const closeWhenHidden = () => {
      if (document.visibilityState === "hidden") {
        resetTypeahead();
        setOpen(false);
      }
    };
    document.addEventListener("pointerdown", closeOutside);
    document.addEventListener("visibilitychange", closeWhenHidden);
    return () => {
      document.removeEventListener("pointerdown", closeOutside);
      document.removeEventListener("visibilitychange", closeWhenHidden);
    };
  }, [open]);

  useEffect(() => () => {
    if (typeaheadTimerRef.current !== undefined) window.clearTimeout(typeaheadTimerRef.current);
  }, []);

  const publishValue = (nextValue: string) => {
    if (nextValue === resolvedValue) return;
    if (!controlled) setInternalValue(nextValue);
    const select = selectRef.current;
    if (!select) return;
    const nativeSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")?.set;
    if (nativeSetter) nativeSetter.call(select, nextValue);
    else select.value = nextValue;
    select.dispatchEvent(new Event("input", { bubbles: true }));
    select.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const choose = (index: number) => {
    const option = options[index];
    if (!option || option.disabled || unavailable) return;
    const focusOwner = document.activeElement;
    resetTypeahead();
    publishValue(option.value);
    setActiveIndex(index);
    setOpen(false);
    // A portaled option never keeps focus. Restore the visible combobox only
    // while focus still belongs to the disclosure that initiated selection.
    // If the operator or browser has already advanced to another control, a
    // delayed WebKit frame must not steal focus back to this selector.
    window.requestAnimationFrame(() => {
      const current = document.activeElement;
      if (current === focusOwner || current === document.body || listboxRef.current?.contains(current)) {
        triggerRef.current?.focus({ preventScroll: true });
      }
    });
  };

  const disclose = () => {
    if (unavailable) return;
    resetTypeahead();
    setActiveIndex(selectedIndex >= 0 && !options[selectedIndex]?.disabled
      ? selectedIndex
      : boundaryEnabledOption(options, 1));
    setOpen((current) => !current);
  };

  const handleKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>) => {
    if (unavailable) return;
    if (event.key === "Tab") {
      resetTypeahead();
      setOpen(false);
      return;
    }
    if (event.key === "Escape") {
      if (open) {
        event.preventDefault();
        // A portaled selector can be opened inside another application-owned
        // modal surface. Consume Escape at the innermost disclosure so the
        // parent dialog remains mounted and focus returns to this trigger.
        event.stopPropagation();
      }
      resetTypeahead();
      setOpen(false);
      return;
    }
    if (event.key === "Enter" || (event.key === " " && typeaheadRef.current.length === 0)) {
      event.preventDefault();
      if (open) choose(activeIndex);
      else disclose();
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      resetTypeahead();
      const direction = event.key === "ArrowDown" ? 1 : -1;
      if (!open) {
        setOpen(true);
        setActiveIndex(selectedIndex >= 0 && !options[selectedIndex]?.disabled
          ? selectedIndex
          : boundaryEnabledOption(options, direction));
      } else {
        setActiveIndex((current) => nextEnabledOption(options, current, direction));
      }
      return;
    }
    if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      resetTypeahead();
      setOpen(true);
      setActiveIndex(boundaryEnabledOption(options, event.key === "Home" ? 1 : -1));
      return;
    }
    if (event.key.length !== 1 || event.ctrlKey || event.metaKey || event.altKey) return;
    const query = `${typeaheadRef.current}${event.key}`.toLocaleLowerCase();
    typeaheadRef.current = query;
    if (typeaheadTimerRef.current !== undefined) window.clearTimeout(typeaheadTimerRef.current);
    typeaheadTimerRef.current = window.setTimeout(() => {
      typeaheadRef.current = "";
      typeaheadTimerRef.current = undefined;
    }, 650);
    const match = findTitaniumTypeaheadIndex(options, query);
    if (match >= 0) {
      event.preventDefault();
      if (open) setActiveIndex(match);
      else choose(match);
    }
  };

  const describedBy = [ariaDescribedBy, error ? errorId : undefined].filter(Boolean).join(" ") || undefined;
  const listbox = open ? (
    <div
      ref={listboxRef}
      id={listboxId}
      className="os-titanium-select__listbox"
      role="listbox"
      aria-label={`${ariaLabel ?? derivedLabel} options`}
      data-top-layer="true"
      data-positioning="sheet"
    >
      <span className="os-titanium-select__rail" aria-hidden="true" />
      {options.map((option, index) => (
        <button
          type="button"
          id={`${listboxId}-option-${index}`}
          key={`${option.value}-${index}`}
          data-select-value={option.value}
          className={`os-titanium-select__option ${index === activeIndex ? "is-active" : ""} ${option.value === resolvedValue ? "is-selected" : ""}`}
          role="option"
          aria-label={option.label}
          aria-selected={option.value === resolvedValue}
          aria-disabled={option.disabled || undefined}
          tabIndex={-1}
          disabled={option.disabled}
          onPointerMove={() => { if (!option.disabled) setActiveIndex(index); }}
          onPointerDown={(event) => event.preventDefault()}
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            choose(index);
          }}
        >
          <span aria-hidden="true" className="os-titanium-select__index">{String(index + 1).padStart(2, "0")}</span>
          <span>{option.label}</span>
          <span aria-hidden="true" className="os-titanium-select__lock" />
        </button>
      ))}
    </div>
  ) : null;
  const portalHost = open ? rootRef.current?.closest<HTMLElement>(".ti-scale") ?? null : null;

  return (
    <span
      ref={rootRef}
      className={`os-titanium-select ${open ? "is-open" : ""} ${error ? "has-error" : ""} ${loading ? "is-loading" : ""}`}
      data-select-state={loading ? "loading" : error ? "error" : disabled ? "disabled" : open ? "open" : "ready"}
      data-select-controlled={controlled ? "controlled" : "uncontrolled"}
    >
      <button
        ref={triggerRef}
        id={selectId}
        type="button"
        role="combobox"
        data-control-id={dataControlId}
        className={`os-titanium-select__trigger ${className}`}
        disabled={unavailable}
        autoFocus={autoFocus}
        title={title}
        aria-label={ariaLabelledBy ? undefined : ariaLabel ?? derivedLabel}
        aria-labelledby={ariaLabelledBy}
        aria-describedby={describedBy}
        aria-busy={loading || undefined}
        aria-invalid={Boolean(error) || undefined}
        aria-required={required || undefined}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listboxId}
        aria-activedescendant={open && activeIndex >= 0 ? `${listboxId}-option-${activeIndex}` : undefined}
        onClick={disclose}
        onKeyDown={handleKeyDown}
      >
        <span className="os-titanium-select__value">{selectedOption?.label || "Select an option"}</span>
        <span className="os-titanium-select__mechanism" aria-hidden="true"><i /><i /><i /></span>
      </button>
      <select
        {...selectProps}
        ref={selectRef}
        id={proxyId}
        className="os-titanium-select__form-proxy"
        value={resolvedValue}
        disabled={unavailable}
        required={required}
        aria-hidden="true"
        tabIndex={-1}
        onInvalid={(event) => {
          onInvalid?.(event);
          if (!event.defaultPrevented) {
            event.preventDefault();
            triggerRef.current?.focus();
          }
        }}
        onChange={(event) => {
          if (!controlled) setInternalValue(event.target.value);
          setOpen(false);
          onChange?.(event);
        }}
      >
        {children}
      </select>
      {listbox && portalHost ? createPortal(listbox, portalHost) : listbox}
      {error && <span id={errorId} className="os-titanium-select__error" role="alert">{error}</span>}
    </span>
  );
}
