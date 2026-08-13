import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as api from './api';

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{"users":[]}', { status: 200 })));
});

describe('api urls', () => {
  it('listUsers passes instance in query', async () => {
    await api.listUsers('beelink102');
    expect((fetch as any).mock.calls[0][0]).toBe('/ss/dashboard/api/users?instance=beelink102');
  });
  it('updateUser encodes id in path', async () => {
    await api.updateUser('beelink102', 'a/b', { enabled: false });
    expect((fetch as any).mock.calls[0][0]).toBe('/ss/dashboard/api/users/a%2Fb?instance=beelink102');
  });
});

describe('mutating calls always carry a JSON content-type', () => {
  // Regression test: deleteUser used to hand-roll `{ method: 'DELETE' }`
  // with no headers at all. The Rust origin gate
  // (bins/outline-ui/src/origin.rs) treats every non-GET/HEAD/OPTIONS
  // method as body-bearing and rejects it with 415 unless it carries
  // `Content-Type: application/json` — before routing, so the DELETE never
  // reached delete_user. Every mutating call funnels through the same
  // mutate() helper now, so this class of bug can't recur one export at a
  // time.
  it('deleteUser sends DELETE with a JSON content-type', async () => {
    await api.deleteUser('beelink102', 'user-1');
    const init = (fetch as any).mock.calls[0][1];
    expect(init.method).toBe('DELETE');
    expect(init.headers['content-type']).toBe('application/json');
  });

  it('createUser, blockUser and unblockUser also carry the header', async () => {
    await api.createUser('beelink102', { id: 'u1', enabled: true });
    expect((fetch as any).mock.calls[0][1].headers['content-type']).toBe('application/json');

    await api.blockUser('beelink102', 'u1');
    expect((fetch as any).mock.calls[1][1].headers['content-type']).toBe('application/json');

    await api.unblockUser('beelink102', 'u1');
    expect((fetch as any).mock.calls[2][1].headers['content-type']).toBe('application/json');
  });
});
