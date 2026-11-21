import { getMeta } from './api';

export const meta = $state<{ version: string | null }>({ version: null });

let requested = false;

export async function loadMeta(): Promise<void> {
  if (requested) return;
  requested = true;
  try {
    const res = await getMeta();
    if (res?.version) meta.version = res.version;
  } catch {
    // Silent fallback: footer still renders "outline-ui" without version if unreachable.
  }
}

export function resetMeta() {
  meta.version = null;
  requested = false;
}
