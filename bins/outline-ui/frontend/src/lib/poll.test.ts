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

  it('refresh() re-fetches immediately and reschedules the interval from that moment', async () => {
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    const p = createPoll(fn, () => 5000);
    p.start();
    await Promise.resolve();
    expect(fn).toHaveBeenCalledTimes(1);

    // Partway through the interval, a mutation handler calls refresh().
    await vi.advanceTimersByTimeAsync(2000);
    await p.refresh();
    expect(fn).toHaveBeenCalledTimes(2);

    // The original timer (3000ms of its 5000ms left) must not also fire —
    // refresh() replaces it with a fresh 5000ms countdown, not stack a second one.
    await vi.advanceTimersByTimeAsync(3000);
    expect(fn).toHaveBeenCalledTimes(2);

    // A full interval after the refresh, polling resumes normally.
    await vi.advanceTimersByTimeAsync(2000);
    expect(fn).toHaveBeenCalledTimes(3);

    p.stop();
    vi.useRealTimers();
  });

  it('refresh() still resolves a fetch when called on a stopped poll, without restarting the schedule', async () => {
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    const p = createPoll(fn, () => 5000);
    // Never started.
    await p.refresh();
    expect(fn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(20000);
    // No timer was armed (poll was never `alive`), so no further calls.
    expect(fn).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });
});
