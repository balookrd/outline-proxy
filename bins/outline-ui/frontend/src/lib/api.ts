import type {
  InstancesResponse,
  User,
  NewUser,
  PatchUser,
  ServerDefaults,
  TopologyResponse,
  ActivateBody,
  ActivateResponse,
  ProxyOpResult,
  RoutesListResponse,
  RouteMutationResponse,
  GroupsListResponse,
  GroupMutationResponse,
} from './types';

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { cache: 'no-store', ...init });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body as any)?.error || `HTTP ${res.status}`);
  return body as T;
}
const q = (instance: string) => `instance=${encodeURIComponent(instance)}`;
const seg = (id: string) => encodeURIComponent(id);

// Every mutating verb funnels through here, so none can forget the
// `content-type` header the Rust origin gate requires on any non-GET/HEAD/
// OPTIONS request (bins/outline-ui/src/origin.rs: `method_carries_body` +
// the JSON content-type check ahead of routing). A bare `{ method: 'DELETE'
// }` with no headers is exactly what deleteUser used to send — it cleared
// routing never, rejected 415 by the gate every time. `body` is omitted
// (rather than serialized as `null`) when absent, so a header-only DELETE
// still carries no body, same as before this helper existed.
const mutate = (method: 'POST' | 'PATCH' | 'DELETE', body?: unknown): RequestInit => ({
  method,
  headers: { 'content-type': 'application/json' },
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});

export const listInstances = (base: '/ss'|'/ws') => json<InstancesResponse>(`${base}/dashboard/api/instances`);

// SS
export const listUsers   = (i: string) => json<{ users: User[] }>(`/ss/dashboard/api/users?${q(i)}`).then(r => r.users);
export const getDefaults = (i: string) => json<ServerDefaults>(`/ss/dashboard/api/defaults?${q(i)}`);
export const createUser  = (i: string, u: NewUser)  => json<User>(`/ss/dashboard/api/users?${q(i)}`, mutate('POST', u));
export const updateUser  = (i: string, id: string, p: PatchUser) =>
  json<User>(`/ss/dashboard/api/users/${seg(id)}?${q(i)}`, mutate('PATCH', p));
export const deleteUser  = (i: string, id: string) =>
  json<unknown>(`/ss/dashboard/api/users/${seg(id)}?${q(i)}`, mutate('DELETE'));
export const blockUser   = (i: string, id: string) => json<User>(`/ss/dashboard/api/users/${seg(id)}/block?${q(i)}`, mutate('POST', {}));
export const unblockUser = (i: string, id: string) => json<User>(`/ss/dashboard/api/users/${seg(id)}/unblock?${q(i)}`, mutate('POST', {}));

// WS
export const topology  = (i: string) => json<TopologyResponse>(`/ws/dashboard/api/topology?${q(i)}`);
export const activate  = (b: ActivateBody) => json<ActivateResponse>(`/ws/dashboard/api/activate`, mutate('POST', b));
export const reselect  = (b: { instance: string; group: string; soft: boolean }) =>
  json<ProxyOpResult>(`/ws/dashboard/api/reselect`, mutate('POST', b));
export const setEnabled = (b: { instance: string; group: string; uplink: string; enabled: boolean }) =>
  json<ProxyOpResult>(`/ws/dashboard/api/set_enabled`, mutate('POST', b));
export const apply = (instance: string) => json<unknown>(`/ws/dashboard/api/apply`, mutate('POST', { instance }));

// WS uplinks CRUD — proxied to /control/uplinks (ws/api.rs `uplinks_proxy`).
// GET carries `instance` + any extra filters (e.g. `group`/`name`, see
// uplinks_crud/list.rs) in the query string; POST/PATCH/DELETE carry an
// `{instance, body}` envelope, same shape ws/uplinks.html's callProxy() used.
export const uplinksList = (i: string, filters: Record<string, string> = {}) =>
  json<any>(`/ws/dashboard/api/uplinks?${new URLSearchParams({ instance: i, ...filters })}`);
export const uplinksMutate = (method: 'POST' | 'PATCH' | 'DELETE', i: string, body: unknown) =>
  json<any>(`/ws/dashboard/api/uplinks`, mutate(method, { instance: i, body }));
// Reorder one uplink within its group — its own POST endpoint (ws/api.rs
// uplinks_reorder_proxy → /control/uplinks/reorder). `body` is {group, name,
// to}: move `name` to 0-based position `to` among its group's uplinks. Order
// is cosmetic (selection is by weight/RTT), so this only rewrites config order.
export const uplinksReorder = (i: string, body: { group: string; name: string; to: number }) =>
  json<any>(`/ws/dashboard/api/uplinks/reorder`, mutate('POST', { instance: i, body }));

// WS routing CRUD — proxied to /control/routes (ws/api.rs routes_proxy). GET
// carries `instance`; POST/PATCH/DELETE carry an {instance, body} envelope;
// reorder is its own POST endpoint. `body` always includes the `revision`
// last read, so a concurrent edit is rejected 409 instead of moving the wrong
// rule (routes_crud mutate revision-guard).
export const routesList = (i: string) =>
  json<RoutesListResponse>(`/ws/dashboard/api/routes?${q(i)}`);
export const routesMutate = (method: 'POST' | 'PATCH' | 'DELETE', i: string, body: unknown) =>
  json<RouteMutationResponse>(`/ws/dashboard/api/routes`, mutate(method, { instance: i, body }));
export const routesReorder = (i: string, body: unknown) =>
  json<RouteMutationResponse>(`/ws/dashboard/api/routes/reorder`, mutate('POST', { instance: i, body }));

// WS uplink-group CRUD — proxied to /control/uplink_groups (ws/api.rs
// groups_proxy). GET carries `instance`; POST/PATCH/DELETE carry an
// {instance, body} envelope. Named-entry (by group name), no revision.
// Reorder is its own POST endpoint ({name, to}), like uplinks/routes reorder.
export const groupsList = (i: string) =>
  json<GroupsListResponse>(`/ws/dashboard/api/groups?${q(i)}`);
export const groupsMutate = (method: 'POST' | 'PATCH' | 'DELETE', i: string, body: unknown) =>
  json<GroupMutationResponse>(`/ws/dashboard/api/groups`, mutate(method, { instance: i, body }));
export const groupsReorder = (i: string, body: { name: string; to: number }) =>
  json<GroupMutationResponse>(`/ws/dashboard/api/groups/reorder`, mutate('POST', { instance: i, body }));
