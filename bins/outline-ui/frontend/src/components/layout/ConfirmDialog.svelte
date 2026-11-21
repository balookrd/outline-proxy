<script lang="ts">
  let {
    open = $bindable(false),
    title,
    message,
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    danger = false,
    onconfirm,
    oncancel,
  }: {
    open: boolean;
    title: string;
    message: string;
    confirmLabel?: string;
    cancelLabel?: string;
    danger?: boolean;
    onconfirm: () => void;
    oncancel?: () => void;
  } = $props();

  let dialogEl: HTMLDialogElement | undefined;
  let pressedOutside = false;

  const titleId = `confirm-title-${Math.random().toString(36).slice(2, 8)}`;

  $effect(() => {
    const el = dialogEl;
    if (!el) return;
    if (open && !el.open) {
      el.returnValue = '';
      el.showModal();
    } else if (!open && el.open) {
      el.close('cancel');
    }
  });

  function isOutside(e: PointerEvent, el: HTMLDialogElement): boolean {
    const r = el.getBoundingClientRect();
    return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
  }

  function onPointerDown(e: PointerEvent) {
    if (!dialogEl || 'closedBy' in HTMLDialogElement.prototype) return;
    pressedOutside = isOutside(e, dialogEl);
  }

  function onPointerUp(e: PointerEvent) {
    if (!dialogEl || 'closedBy' in HTMLDialogElement.prototype) return;
    if (pressedOutside && isOutside(e, dialogEl)) {
      dialogEl.close('cancel');
    }
    pressedOutside = false;
  }

  function onClose() {
    if (!dialogEl) return;
    const rv = dialogEl.returnValue;
    dialogEl.returnValue = '';
    open = false;
    if (rv === 'confirm') {
      onconfirm();
    } else {
      oncancel?.();
    }
  }
</script>

<!-- Native modal <dialog> provides inert page, focus trap, Esc dismissal, and focus return. -->
<dialog
  bind:this={dialogEl}
  class="ui-dialog confirm-dialog"
  closedby="any"
  aria-labelledby={titleId}
  onclose={onClose}
  onpointerdown={onPointerDown}
  onpointerup={onPointerUp}
>
  <form method="dialog" class="dialog-card">
    <header class="dialog-head">
      <h2 id={titleId}>{title}</h2>
    </header>
    <p class="dialog-body-text">{message}</p>
    <footer class="dialog-foot">
      <!-- svelte-ignore a11y_autofocus -->
      <button type="submit" value="cancel" class="btn ghost" autofocus>{cancelLabel}</button>
      <button type="submit" value="confirm" class={danger ? 'btn danger' : 'btn primary'}>
        {confirmLabel}
      </button>
    </footer>
  </form>
</dialog>
