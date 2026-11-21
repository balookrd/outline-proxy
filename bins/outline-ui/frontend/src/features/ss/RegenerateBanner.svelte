<script lang="ts">
  let {
    visible,
    restartPendingNodes = [],
    regenerating = false,
    onRegenerate,
    onDismiss,
  }: {
    visible: boolean;
    restartPendingNodes: string[];
    regenerating?: boolean;
    onRegenerate: () => void;
    onDismiss: () => void;
  } = $props();
</script>

{#if visible}
  {#if restartPendingNodes.length > 0}
    <div class="applybar" role="status" aria-live="polite">
      <span class="pill">RESTART PENDING</span>
      <span>
        Saved to config on <strong class="mono">{restartPendingNodes.join(', ')}</strong>. Restart nodes one at a time via systemd/CLI to apply listener/carrier/tuning changes, then regenerate subscriptions if endpoints changed.
      </span>
      <span class="spacer"></span>
      <button type="button" class="btn sm" disabled={regenerating} onclick={onRegenerate}>
        {regenerating ? 'Regenerating…' : 'Regenerate subscriptions'}
      </button>
      <button type="button" class="btn ghost sm" onclick={onDismiss}>Dismiss</button>
    </div>
  {:else}
    <div class="info-banner" role="status" aria-live="polite">
      <span>Settings saved without requiring server restart. Regenerate subscription links/configs to publish updates.</span>
      <span class="spacer"></span>
      <button type="button" class="btn primary sm" disabled={regenerating} onclick={onRegenerate}>
        {regenerating ? 'Regenerating…' : 'Regenerate subscriptions'}
      </button>
      <button type="button" class="btn ghost sm" onclick={onDismiss}>Dismiss</button>
    </div>
  {/if}
{/if}
