import { expect, type Page, type Route } from '@playwright/test';
import {
  makeAccessKeysBundle,
  makeApplyResult,
  makeClusterConfigResponse,
  makeClusterMutationResponse,
  makeClusterRegenerateResponse,
  makeClusterUsersResponse,
  makeDefaults,
  makeGroupsResponse,
  makeMeta,
  makeRegenerateReport,
  makeRoutesResponse,
  makeServerConfig,
  makeSingleUsers,
  makeSsInstances,
  makeTopologyResponse,
  makeUplinksResponse,
  makeWsConfigMutationResponse,
  makeWsConfigResponse,
  makeWsInstances,
} from '../src/test/fixtures.ts';
import type { ClusterUser, RouteConfig, UplinkConfig } from '../src/lib/types.ts';

export interface RecordedE2ECall {
  method: string;
  url: string;
  pathname: string;
  searchParams: URLSearchParams;
  headers: Record<string, string>;
  body: unknown;
}

export interface E2EMockOverride {
  method?: string;
  match: string | RegExp | ((call: RecordedE2ECall) => boolean);
  handler: (call: RecordedE2ECall) => { status?: number; body?: unknown } | Promise<{ status?: number; body?: unknown }>;
}

export interface ErrorGuard {
  errors: string[];
  assertClean(): void;
}

export function attachErrorGuard(page: Page): ErrorGuard {
  const errors: string[] = [];

  page.on('pageerror', (err) => {
    errors.push(`pageerror: ${err.message}`);
  });
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      errors.push(`console.error: ${msg.text()}`);
    }
  });
  page.on('response', (res) => {
    const pathname = new URL(res.url()).pathname;
    if ((pathname.startsWith('/ui-assets/') || pathname.startsWith('/favicon')) && res.status() >= 400) {
      errors.push(`asset HTTP ${res.status()} for ${pathname}`);
    }
  });

  return {
    errors,
    assertClean() {
      expect(errors, `Browser errors detected:\n${errors.join('\n')}`).toEqual([]);
    },
  };
}

const MUTATING_METHODS = new Set(['POST', 'PATCH', 'DELETE', 'PUT']);

function parseJsonBody(raw: string | null): unknown {
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

async function fulfillJson(route: Route, status: number, body: unknown) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body ?? {}),
  });
}

export async function mockOutlineApi(page: Page, overrides: E2EMockOverride[] = []) {
  const calls: RecordedE2ECall[] = [];

  const ssClusterUsers: Record<string, ReturnType<typeof makeClusterUsersResponse>> = {
    cloud: makeClusterUsersResponse('cloud'),
    'nuxt+nuxt2': makeClusterUsersResponse('nuxt+nuxt2'),
  };
  const ssClusterConfigs: Record<string, ReturnType<typeof makeClusterConfigResponse>> = {
    cloud: makeClusterConfigResponse('cloud'),
    'nuxt+nuxt2': makeClusterConfigResponse('nuxt+nuxt2'),
  };
  const singleUsers = makeSingleUsers();
  const singleServerConfig = makeServerConfig();
  const uplinksState = makeUplinksResponse();
  const groupsState = makeGroupsResponse();
  const routesState = makeRoutesResponse('rev-1');
  let routesSeq = 1;
  let wsConfigState = makeWsConfigResponse();

  await page.route(/^http:\/\/127\.0\.0\.1:\d+\/(api|ss\/dashboard\/api|ws\/dashboard\/api)\//, async (route) => {
    const req = route.request();
    const rawUrl = req.url();
    const parsed = new URL(rawUrl);
    const method = req.method().toUpperCase();
    const headers = await req.allHeaders();
    const body = parseJsonBody(req.postData());

    const call: RecordedE2ECall = {
      method,
      url: rawUrl,
      pathname: parsed.pathname,
      searchParams: parsed.searchParams,
      headers,
      body,
    };
    calls.push(call);

    if (MUTATING_METHODS.has(method)) {
      const ct = headers['content-type'] ?? '';
      if (!ct.toLowerCase().includes('application/json')) {
        await fulfillJson(route, 415, { error: 'Unsupported Media Type: expected application/json' });
        return;
      }
    }

    for (const ov of overrides) {
      if (ov.method && ov.method.toUpperCase() !== method) continue;
      const matched =
        typeof ov.match === 'string'
          ? parsed.pathname === ov.match
          : ov.match instanceof RegExp
            ? ov.match.test(rawUrl) || ov.match.test(parsed.pathname)
            : ov.match(call);
      if (matched) {
        const res = await ov.handler(call);
        await fulfillJson(route, res.status ?? 200, res.body);
        return;
      }
    }

    const p = parsed.pathname;

    if (method === 'GET') {
      if (p === '/api/meta') return fulfillJson(route, 200, makeMeta());
      if (p === '/ss/dashboard/api/instances') return fulfillJson(route, 200, makeSsInstances());
      if (p === '/ss/dashboard/api/clusters') {
        return fulfillJson(route, 200, { clusters: makeSsInstances().clusters ?? [] });
      }
      if (p === '/ss/dashboard/api/users') return fulfillJson(route, 200, { users: singleUsers });
      if (p === '/ss/dashboard/api/defaults') return fulfillJson(route, 200, makeDefaults());
      if (p === '/ss/dashboard/api/config') return fulfillJson(route, 200, singleServerConfig);

      let m = /^\/ss\/dashboard\/api\/users\/([^/]+)\/access-keys$/.exec(p);
      if (m) return fulfillJson(route, 200, makeAccessKeysBundle('cluster', decodeURIComponent(m[1])));

      m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/users$/.exec(p);
      if (m) {
        const name = decodeURIComponent(m[1]);
        const res = ssClusterUsers[name] ?? makeClusterUsersResponse(name);
        return fulfillJson(route, 200, res);
      }
      m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/defaults$/.exec(p);
      if (m) return fulfillJson(route, 200, makeDefaults());

      m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/config$/.exec(p);
      if (m) {
        const name = decodeURIComponent(m[1]);
        return fulfillJson(route, 200, ssClusterConfigs[name] ?? makeClusterConfigResponse(name));
      }
      m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/users\/([^/]+)\/access-keys$/.exec(p);
      if (m) {
        return fulfillJson(route, 200, makeAccessKeysBundle('cluster', decodeURIComponent(m[2])));
      }

      if (p === '/ws/dashboard/api/instances') return fulfillJson(route, 200, makeWsInstances());
      if (p === '/ws/dashboard/api/topology') {
        return fulfillJson(route, 200, makeTopologyResponse(parsed.searchParams.get('instance') ?? 'beelink102'));
      }
      if (p === '/ws/dashboard/api/uplinks') return fulfillJson(route, 200, uplinksState);
      if (p === '/ws/dashboard/api/groups') return fulfillJson(route, 200, groupsState);
      if (p === '/ws/dashboard/api/routes') return fulfillJson(route, 200, routesState);
      if (p === '/ws/dashboard/api/config') return fulfillJson(route, 200, wsConfigState);
    }

    // Stateful SS cluster user CRUD
    let m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/users$/.exec(p);
    if (m && method === 'POST') {
      const name = decodeURIComponent(m[1]);
      const store = ssClusterUsers[name] ?? makeClusterUsersResponse(name);
      const payload = body as { id: string; method?: string; enabled?: boolean };
      const nextUser: ClusterUser = {
        id: payload.id,
        enabled: payload.enabled ?? true,
        method: payload.method ?? null,
        has_password: true,
        has_vless_id: false,
        sync_status: 'synced',
        present_on: [...store.members],
        missing_on: [],
        diff_fields: [],
        per_node: {},
      };
      store.users.push(nextUser);
      return fulfillJson(route, 200, makeClusterMutationResponse(store.members));
    }

    m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/users\/([^/]+)$/.exec(p);
    if (m && method === 'DELETE') {
      const name = decodeURIComponent(m[1]);
      const uid = decodeURIComponent(m[2]);
      const store = ssClusterUsers[name] ?? makeClusterUsersResponse(name);
      store.users = store.users.filter((u) => u.id !== uid);
      return fulfillJson(route, 200, makeClusterMutationResponse(store.members));
    }

    m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/config$/.exec(p);
    if (m && method === 'PATCH') {
      const name = decodeURIComponent(m[1]);
      const store = ssClusterConfigs[name] ?? makeClusterConfigResponse(name);
      return fulfillJson(route, 200, makeClusterMutationResponse(store.members));
    }

    m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/access-keys\/regenerate$/.exec(p);
    if (m && method === 'POST') {
      return fulfillJson(route, 200, makeClusterRegenerateResponse(decodeURIComponent(m[1])));
    }

    if (p === '/ss/dashboard/api/access-keys/regenerate' && method === 'POST') {
      return fulfillJson(route, 200, makeRegenerateReport());
    }

    // Stateful WS operations
    if (p === '/ws/dashboard/api/activate' && method === 'POST') {
      return fulfillJson(route, 200, {
        results: [{ target: { instance: 'beelink102', group: 'main', uplink: 'beelink102-backup' }, ok: true, status: 200, body: { ok: true }, error: null }],
      });
    }
    if ((p === '/ws/dashboard/api/reselect' || p === '/ws/dashboard/api/set_enabled') && method === 'POST') {
      return fulfillJson(route, 200, { ok: true, body: { ok: true } });
    }
    if (p === '/ws/dashboard/api/apply' && method === 'POST') {
      return fulfillJson(route, 200, makeApplyResult());
    }
    if (p === '/ws/dashboard/api/uplinks' && method === 'POST') {
      const env = body as { body: { group: string; uplink: UplinkConfig & { name: string } } };
      uplinksState.uplinks.push({
        group: env.body.group,
        name: env.body.uplink.name,
        index: uplinksState.uplinks.length,
        config: env.body.uplink,
      });
      return fulfillJson(route, 200, { ok: true });
    }
    if (p === '/ws/dashboard/api/uplinks' && (method === 'PATCH' || method === 'DELETE')) {
      return fulfillJson(route, 200, { ok: true });
    }
    if (p === '/ws/dashboard/api/groups' && method === 'DELETE') {
      const env = body as { body: { name: string } };
      groupsState.groups = groupsState.groups.filter((g) => g.name !== env.body.name);
      return fulfillJson(route, 200, { name: env.body.name, action: 'delete', apply_required: true });
    }
    if (p.startsWith('/ws/dashboard/api/groups') && MUTATING_METHODS.has(method)) {
      return fulfillJson(route, 200, { name: 'main', action: method.toLowerCase(), apply_required: true });
    }
    if (p === '/ws/dashboard/api/routes' && method === 'POST') {
      const env = body as { body: { rule: RouteConfig } };
      const idx = Math.max(0, routesState.routes.length - 1);
      routesState.routes.splice(idx, 0, { index: idx, is_default: false, config: env.body.rule });
      routesState.routes.forEach((r, i) => { r.index = i; });
      routesState.revision = `rev-${++routesSeq}`;
      return fulfillJson(route, 200, { action: 'create', index: idx, apply_required: true, revision: routesState.revision });
    }
    if (p.startsWith('/ws/dashboard/api/routes') && MUTATING_METHODS.has(method)) {
      routesState.revision = `rev-${++routesSeq}`;
      return fulfillJson(route, 200, { action: method.toLowerCase(), index: 0, apply_required: true, revision: routesState.revision });
    }
    if (p === '/ws/dashboard/api/config' && method === 'PATCH') {
      wsConfigState = { ...wsConfigState, ...(body as Record<string, unknown>) };
      return fulfillJson(route, 200, makeWsConfigMutationResponse({ restart_required: true, apply_required: true }));
    }

    await fulfillJson(route, 404, { error: `Unmocked ${method} ${p}` });
  });

  return {
    calls,
    callsFor(method: string, pathPart: string | RegExp) {
      const m = method.toUpperCase();
      return calls.filter((c) => {
        if (c.method !== m) return false;
        return typeof pathPart === 'string' ? c.url.includes(pathPart) : pathPart.test(c.url);
      });
    },
  };
}
