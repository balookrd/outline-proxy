import type {
  InstancesResponse,
  User,
  NewUser,
  PatchUser,
  TopologyResponse,
  ActivateBody,
  ActivateResponse,
  ProxyOpResult,
} from './types';

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { cache: 'no-store', ...init });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body as any)?.error || `HTTP ${res.status}`);
  return body as T;
}
const q = (instance: string) => `instance=${encodeURIComponent(instance)}`;
const seg = (id: string) => encodeURIComponent(id);
const post = (body: unknown): RequestInit =>
  ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

export const listInstances = (base: '/ss'|'/ws') => json<InstancesResponse>(`${base}/dashboard/api/instances`);

// SS
export const listUsers   = (i: string) => json<{ users: User[] }>(`/ss/dashboard/api/users?${q(i)}`).then(r => r.users);
export const createUser  = (i: string, u: NewUser)  => json<User>(`/ss/dashboard/api/users?${q(i)}`, post(u));
export const updateUser  = (i: string, id: string, p: PatchUser) =>
  json<User>(`/ss/dashboard/api/users/${seg(id)}?${q(i)}`, { ...post(p), method: 'PATCH' });
export const deleteUser  = (i: string, id: string) =>
  json<unknown>(`/ss/dashboard/api/users/${seg(id)}?${q(i)}`, { method: 'DELETE' });
export const blockUser   = (i: string, id: string) => json<User>(`/ss/dashboard/api/users/${seg(id)}/block?${q(i)}`, post({}));
export const unblockUser = (i: string, id: string) => json<User>(`/ss/dashboard/api/users/${seg(id)}/unblock?${q(i)}`, post({}));

// WS
export const topology  = (i: string) => json<TopologyResponse>(`/ws/dashboard/api/topology?${q(i)}`);
export const activate  = (b: ActivateBody) => json<ActivateResponse>(`/ws/dashboard/api/activate`, post(b));
export const reselect  = (b: { instance: string; group: string; soft: boolean }) =>
  json<ProxyOpResult>(`/ws/dashboard/api/reselect`, post(b));
export const setEnabled = (b: { instance: string; group: string; uplink: string; enabled: boolean }) =>
  json<ProxyOpResult>(`/ws/dashboard/api/set_enabled`, post(b));
export const apply = (instance: string) => json<unknown>(`/ws/dashboard/api/apply`, post({ instance }));

// WS uplinks CRUD — proxied to /control/uplinks (ws/api.rs `uplinks_proxy`).
// GET carries `instance` + any extra filters (e.g. `group`/`name`, see
// uplinks_crud/list.rs) in the query string; POST/PATCH/DELETE carry an
// `{instance, body}` envelope, same shape ws/uplinks.html's callProxy() used.
export const uplinksList = (i: string, filters: Record<string, string> = {}) =>
  json<any>(`/ws/dashboard/api/uplinks?${new URLSearchParams({ instance: i, ...filters })}`);
export const uplinksMutate = (method: 'POST' | 'PATCH' | 'DELETE', i: string, body: unknown) =>
  json<any>(`/ws/dashboard/api/uplinks`, { ...post({ instance: i, body }), method });
