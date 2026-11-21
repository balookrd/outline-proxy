import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/svelte';
import { afterEach, vi } from 'vitest';
import { resetMeta } from '../lib/meta.svelte';
import { route } from '../lib/router.svelte';
import { resetSsTargets } from '../lib/ssTarget.svelte';
import { theme } from '../lib/theme.svelte';
import { clearToasts } from '../lib/toast.svelte';

function createMemoryStorage(): Storage {
  const store = new Map<string, string>();
  return {
    get length() {
      return store.size;
    },
    clear() {
      store.clear();
    },
    getItem(key: string) {
      return store.get(String(key)) ?? null;
    },
    key(index: number) {
      return Array.from(store.keys())[index] ?? null;
    },
    removeItem(key: string) {
      store.delete(String(key));
    },
    setItem(key: string, value: string) {
      store.set(String(key), String(value));
    },
  };
}

function installLocalStoragePolyfill() {
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage?.getItem === 'function') {
      if (typeof globalThis.localStorage?.getItem !== 'function') {
        Object.defineProperty(globalThis, 'localStorage', {
          configurable: true,
          value: window.localStorage,
        });
      }
      return;
    }
  } catch {
    // Node experimental localStorage getter may return undefined or throw without --localstorage-file.
  }
  const storage = createMemoryStorage();
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: storage,
  });
  if (typeof window !== 'undefined') {
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      value: storage,
    });
  }
}

function installMatchMediaFallback() {
  if (typeof window === 'undefined') return;
  if (typeof window.matchMedia === 'function') return;
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}

function installDialogPolyfill() {
  if (typeof HTMLDialogElement === 'undefined') return;
  const proto = HTMLDialogElement.prototype as HTMLDialogElement & {
    __outlinePolyfilled?: boolean;
    closedBy?: string;
  };
  if (proto.__outlinePolyfilled) return;
  proto.__outlinePolyfilled = true;

  const returnValues = new WeakMap<HTMLDialogElement, string>();

  if (!('closedBy' in proto)) {
    Object.defineProperty(proto, 'closedBy', {
      configurable: true,
      get() {
        return this.getAttribute('closedby') ?? 'none';
      },
      set(val: string) {
        this.setAttribute('closedby', val);
      },
    });
  }

  Object.defineProperty(proto, 'open', {
    configurable: true,
    get() {
      return this.hasAttribute('open');
    },
    set(val: boolean) {
      if (val) this.setAttribute('open', '');
      else this.removeAttribute('open');
    },
  });

  Object.defineProperty(proto, 'returnValue', {
    configurable: true,
    get() {
      return returnValues.get(this) ?? '';
    },
    set(val: string) {
      returnValues.set(this, String(val ?? ''));
    },
  });

  proto.show = function show() {
    this.setAttribute('open', '');
  };

  proto.showModal = function showModal() {
    this.setAttribute('open', '');
  };

  proto.close = function close(value?: string) {
    const wasOpen = this.hasAttribute('open');
    if (value !== undefined) {
      this.returnValue = value;
    }
    this.removeAttribute('open');
    if (wasOpen) {
      this.dispatchEvent(new Event('close', { bubbles: false, cancelable: false }));
    }
  };

  if (typeof document !== 'undefined') {
    document.addEventListener(
      'submit',
      (e: SubmitEvent) => {
        const form = e.target;
        if (!(form instanceof HTMLFormElement)) return;
        if (form.getAttribute('method')?.toLowerCase() !== 'dialog') return;
        e.preventDefault();
        const dialog = form.closest('dialog');
        if (!dialog || !(dialog instanceof HTMLDialogElement)) return;
        const submitter = e.submitter as HTMLButtonElement | HTMLInputElement | null;
        const value = submitter?.getAttribute('value') ?? submitter?.value ?? '';
        dialog.close(value);
      },
      true,
    );
  }
}

function installClipboardAndUrlStubs() {
  if (typeof navigator !== 'undefined') {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      writable: true,
      value: {
        writeText: async () => {},
      },
    });
  }
  if (typeof URL !== 'undefined') {
    if (typeof URL.createObjectURL !== 'function') {
      URL.createObjectURL = () => 'blob:mock';
    }
    if (typeof URL.revokeObjectURL !== 'function') {
      URL.revokeObjectURL = () => {};
    }
  }
  if (typeof window !== 'undefined' && typeof window.confirm !== 'function') {
    window.confirm = () => false;
  }
  if (typeof Element !== 'undefined' && typeof Element.prototype.scrollIntoView !== 'function') {
    Element.prototype.scrollIntoView = () => {};
  }
}

function installSelectCheckedPolyfill() {
  if (typeof HTMLSelectElement === 'undefined') return;
  const proto = HTMLSelectElement.prototype as HTMLSelectElement & {
    __outlineSelectCheckedPolyfilled?: boolean;
  };
  if (proto.__outlineSelectCheckedPolyfilled) return;
  proto.__outlineSelectCheckedPolyfilled = true;

  const origQuerySelector = proto.querySelector;
  const origQuerySelectorAll = proto.querySelectorAll;

  proto.querySelector = function querySelector(this: HTMLSelectElement, selector: string) {
    if (selector.trim() === ':checked') {
      return Array.from(this.options).find((o) => o.selected) ?? null;
    }
    return origQuerySelector.call(this, selector);
  } as typeof proto.querySelector;

  proto.querySelectorAll = function querySelectorAll(this: HTMLSelectElement, selector: string) {
    if (selector.trim() === ':checked') {
      return Array.from(this.options).filter((o) => o.selected) as unknown as NodeListOf<Element>;
    }
    return origQuerySelectorAll.call(this, selector);
  } as typeof proto.querySelectorAll;
}

function decimalPlaces(raw: string): number {
  const dot = raw.indexOf('.');
  return dot === -1 ? 0 : raw.length - dot - 1;
}

function installDecimalStepValidityPolyfill() {
  if (typeof document === 'undefined') return;
  const sample = document.createElement('input').validity;
  const proto = Object.getPrototypeOf(sample) as ValidityState & {
    __outlineStepPolyfilled?: boolean;
    element?: HTMLInputElement;
  };
  if (!proto || proto.__outlineStepPolyfilled) return;
  const desc = Object.getOwnPropertyDescriptor(proto, 'stepMismatch');
  if (!desc?.get) return;
  proto.__outlineStepPolyfilled = true;

  Object.defineProperty(proto, 'stepMismatch', {
    configurable: true,
    get() {
      const el = (this as { element?: HTMLInputElement }).element;
      if (el && el.tagName === 'INPUT' && (el.type === 'number' || el.type === 'range')) {
        if (!el.value) return false;
        const stepAttr = el.getAttribute('step');
        if (stepAttr === 'any') return false;
        const stepStr = stepAttr ?? '1';
        const valNum = Number(el.value);
        const stepNum = Number(stepStr);
        if (!Number.isFinite(valNum) || !Number.isFinite(stepNum) || stepNum <= 0) {
          return false;
        }
        const scale = 10 ** Math.max(decimalPlaces(el.value), decimalPlaces(stepStr));
        return Math.round(valNum * scale) % Math.round(stepNum * scale) !== 0;
      }
      return desc.get!.call(this);
    },
  });
}

installLocalStoragePolyfill();
installMatchMediaFallback();
installDialogPolyfill();
installSelectCheckedPolyfill();
installDecimalStepValidityPolyfill();
installClipboardAndUrlStubs();

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();

  resetMeta();
  resetSsTargets();
  clearToasts();
  theme.mode = null;

  if (typeof localStorage !== 'undefined' && typeof localStorage.clear === 'function') {
    localStorage.clear();
  }
  if (typeof document !== 'undefined') {
    document.documentElement.removeAttribute('data-theme');
    document.head.querySelectorAll('meta[name="theme-color"]').forEach((el) => el.remove());
    const favicon = document.getElementById('favicon');
    if (favicon) favicon.remove();
  }
  if (typeof history !== 'undefined') {
    history.replaceState({}, '', '/');
  }
  route.path = '/';
});
