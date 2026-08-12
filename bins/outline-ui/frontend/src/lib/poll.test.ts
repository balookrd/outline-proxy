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

  it('refresh() on a stopped, hidden poll does not leave a self-perpetuating timer running', async () => {
    // Regression test: tick()'s hidden-tab early return used to call
    // schedule() unconditionally, so a refresh() on a stopped
    // (`alive === false`) poll would arm a timer anyway. That timer's own
    // tick() would still see the tab hidden and reschedule itself again —
    // forever — even though stop() was supposed to have ended all polling.
    // fn() is never called while hidden (tick() skips the actual fetch in
    // that branch either way), so the leak is invisible until the tab comes
    // back into view: the leftover timer chain then fires tick() for real
    // and fetches on a poll that was never re-started.
    const doc = { hidden: true };
    vi.stubGlobal('document', doc);
    try {
      vi.useFakeTimers();
      const fn = vi.fn(async () => 1);
      const p = createPoll(fn, () => 5000);
      // Never started.
      await p.refresh();
      expect(fn).toHaveBeenCalledTimes(0);

      // Let any leftover hidden-branch timer chain run for a while, still hidden.
      await vi.advanceTimersByTimeAsync(20000);
      expect(fn).toHaveBeenCalledTimes(0);

      // Tab becomes visible again. A stopped poll must stay stopped: no
      // leftover timer should be waiting to fire now that the hidden guard
      // no longer short-circuits it.
      doc.hidden = false;
      await vi.advanceTimersByTimeAsync(10000);
      expect(fn).toHaveBeenCalledTimes(0);

      vi.useRealTimers();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
