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
