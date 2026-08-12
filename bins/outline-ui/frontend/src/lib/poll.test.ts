import { describe, it, expect, vi } from 'vitest';
import { createPoll } from './poll.svelte';

describe('poll', () => {
  it('runs immediately then on interval; stop() halts', async () => {
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    const p = createPoll(fn, () => 5000);
    p.start();
    await Promise.resolve();
    expect(fn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5000);
    expect(fn).toHaveBeenCalledTimes(2);
    p.stop();
    await vi.advanceTimersByTimeAsync(10000);
    expect(fn).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });
});
