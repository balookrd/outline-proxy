export function createPoll<T>(fn: () => Promise<T>, intervalMs: () => number) {
  const s = $state<{ data: T | null; error: string | null; loading: boolean }>({
    data: null, error: null, loading: false,
  });
  let timer: ReturnType<typeof setTimeout> | null = null;
  let alive = false;

  async function tick() {
    if (typeof document !== 'undefined' && document.hidden) return schedule();
    s.loading = true;
    try { s.data = await fn(); s.error = null; }
    catch (e) { s.error = e instanceof Error ? e.message : String(e); }
    finally { s.loading = false; if (alive) schedule(); }
  }
  function schedule() { if (timer) clearTimeout(timer); timer = setTimeout(tick, Math.max(1000, intervalMs())); }

  return {
    get data() { return s.data; }, get error() { return s.error; }, get loading() { return s.loading; },
    start() { alive = true; tick(); }, stop() { alive = false; if (timer) clearTimeout(timer); timer = null; },
  };
}
