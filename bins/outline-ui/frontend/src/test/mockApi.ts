import { vi } from 'vitest';
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
} from './fixtures';

export interface RecordedCall {
  method: string;
  url: string;
  pathname: string;
  searchParams: URLSearchParams;
  headers: Record<string, string>;
  body: unknown;
}

export interface MockJsonSpec {
  status?: number;
  body?: unknown;
}

export type MockHandlerResult = Response | MockJsonSpec | unknown;
export type MockHandler = (
  call: RecordedCall,
) => MockHandlerResult | Promise<MockHandlerResult>;

export interface MockRouteOverride {
  method?: string;
  match: string | RegExp | ((call: RecordedCall) => boolean);
  handler: MockHandler;
}

export interface FetchMockController {
  calls: RecordedCall[];
  callsFor(method: string, pathPart: string | RegExp): RecordedCall[];
  clearCalls(): void;
}

const MUTATING_METHODS = new Set(['POST', 'PATCH', 'DELETE', 'PUT']);

function normalizeHeaders(headers?: HeadersInit): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  if (headers instanceof Headers) {
    headers.forEach((v, k) => {
      out[k.toLowerCase()] = v;
    });
    return out;
  }
  if (Array.isArray(headers)) {
    for (const [k, v] of headers) {
      out[k.toLowerCase()] = v;
    }
    return out;
  }
  for (const [k, v] of Object.entries(headers)) {
    if (v !== undefined) out[k.toLowerCase()] = v;
  }
  return out;
}

function parseBody(raw: BodyInit | null | undefined): unknown {
  if (typeof raw !== 'string' || !raw.length) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function toResponse(result: MockHandlerResult): Response {
  if (result instanceof Response) return result;
  if (
    result &&
    typeof result === 'object' &&
    ('status' in result || 'body' in result) &&
    Object.keys(result).every((k) => k === 'status' || k === 'body')
  ) {
    const spec = result as MockJsonSpec;
    return new Response(JSON.stringify(spec.body ?? {}), {
      status: spec.status ?? 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  return new Response(JSON.stringify(result ?? {}), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function defaultResponse(call: RecordedCall): MockHandlerResult {
  const { method, pathname, searchParams } = call;

  if (method === 'GET') {
    if (pathname === '/api/meta') return makeMeta();
    if (pathname === '/ss/dashboard/api/instances') return makeSsInstances();
    if (pathname === '/ss/dashboard/api/clusters') {
      return { clusters: makeSsInstances().clusters ?? [] };
    }
    if (pathname === '/ss/dashboard/api/users') return { users: makeSingleUsers() };
    if (pathname === '/ss/dashboard/api/defaults') return makeDefaults();
    if (pathname === '/ss/dashboard/api/config') return makeServerConfig();

    let m = /^\/ss\/dashboard\/api\/users\/([^/]+)\/access-keys$/.exec(pathname);
    if (m) {
      return makeAccessKeysBundle('cluster', decodeURIComponent(m[1]));
    }

    m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/users$/.exec(pathname);
    if (m) {
      return makeClusterUsersResponse(decodeURIComponent(m[1]));
    }

    m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/defaults$/.exec(pathname);
    if (m) {
      return makeDefaults();
    }

    m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/config$/.exec(pathname);
    if (m) {
      return makeClusterConfigResponse(decodeURIComponent(m[1]));
    }

    m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/users\/([^/]+)\/access-keys$/.exec(pathname);
    if (m) {
      return makeAccessKeysBundle('cluster', decodeURIComponent(m[2]));
    }

    if (pathname === '/ws/dashboard/api/instances') return makeWsInstances();
    if (pathname === '/ws/dashboard/api/topology') {
      return makeTopologyResponse(searchParams.get('instance') ?? 'beelink102');
    }
    if (pathname === '/ws/dashboard/api/uplinks') return makeUplinksResponse();
    if (pathname === '/ws/dashboard/api/routes') return makeRoutesResponse();
    if (pathname === '/ws/dashboard/api/groups') return makeGroupsResponse();
    if (pathname === '/ws/dashboard/api/config') return makeWsConfigResponse();
  }

  // Enforce the same JSON content-type origin gate contract as bins/outline-ui/src/origin.rs
  if (MUTATING_METHODS.has(method)) {
    const ct = call.headers['content-type'] ?? '';
    if (!ct.toLowerCase().includes('application/json')) {
      return {
        status: 415,
        body: { error: 'Unsupported Media Type: expected application/json' },
      };
    }
  }

  if (pathname === '/ss/dashboard/api/users' && method === 'POST') {
    return { id: 'new-user', enabled: true };
  }
  if (/^\/ss\/dashboard\/api\/users\/[^/]+$/.test(pathname) && (method === 'PATCH' || method === 'DELETE')) {
    return { ok: true, id: 'alice', enabled: true };
  }
  if (/^\/ss\/dashboard\/api\/users\/[^/]+\/(block|unblock)$/.test(pathname) && method === 'POST') {
    const unblock = pathname.endsWith('/unblock');
    const id = decodeURIComponent(pathname.split('/')[5] ?? 'alice');
    return { id, enabled: unblock };
  }
  if (pathname === '/ss/dashboard/api/config' && method === 'PATCH') {
    return { ok: true, message: 'Saved', requires_restart: false };
  }
  if (pathname === '/ss/dashboard/api/access-keys/regenerate' && method === 'POST') {
    return makeRegenerateReport();
  }

  let m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/users/.exec(pathname);
  if (m && MUTATING_METHODS.has(method)) {
    const cluster = decodeURIComponent(m[1]);
    return makeClusterMutationResponse(cluster === 'nuxt+nuxt2' ? ['nuxt', 'nuxt2'] : ['cloud1', 'cloud2']);
  }
  m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/config$/.exec(pathname);
  if (m && method === 'PATCH') {
    const cluster = decodeURIComponent(m[1]);
    return makeClusterMutationResponse(cluster === 'nuxt+nuxt2' ? ['nuxt', 'nuxt2'] : ['cloud1', 'cloud2']);
  }
  m = /^\/ss\/dashboard\/api\/clusters\/([^/]+)\/access-keys\/regenerate$/.exec(pathname);
  if (m && method === 'POST') {
    return makeClusterRegenerateResponse(decodeURIComponent(m[1]));
  }

  if (pathname === '/ws/dashboard/api/activate' && method === 'POST') {
    return {
      results: [{ target: { instance: 'beelink102', group: 'main', uplink: 'beelink102-backup' }, ok: true, status: 200, body: { ok: true }, error: null }],
    };
  }
  if ((pathname === '/ws/dashboard/api/reselect' || pathname === '/ws/dashboard/api/set_enabled') && method === 'POST') {
    return { ok: true, body: { ok: true } };
  }
  if (pathname === '/ws/dashboard/api/apply' && method === 'POST') {
    return makeApplyResult();
  }
  if (pathname.startsWith('/ws/dashboard/api/uplinks') && MUTATING_METHODS.has(method)) {
    return { ok: true };
  }
  if (pathname.startsWith('/ws/dashboard/api/routes') && MUTATING_METHODS.has(method)) {
    return { action: method.toLowerCase(), index: 0, apply_required: true, revision: 'rev-2' };
  }
  if (pathname.startsWith('/ws/dashboard/api/groups') && MUTATING_METHODS.has(method)) {
    return { name: 'main', action: method.toLowerCase(), apply_required: true };
  }
  if (pathname === '/ws/dashboard/api/config' && method === 'PATCH') {
    return makeWsConfigMutationResponse();
  }

  return { status: 404, body: { error: `Unmocked ${method} ${pathname}` } };
}

function matchesOverride(override: MockRouteOverride, call: RecordedCall): boolean {
  if (override.method && override.method.toUpperCase() !== call.method) return false;
  if (typeof override.match === 'string') return call.pathname === override.match;
  if (override.match instanceof RegExp) return override.match.test(call.url) || override.match.test(call.pathname);
  return override.match(call);
}

export function installFetchMock(overrides: MockRouteOverride[] = []): FetchMockController {
  const calls: RecordedCall[] = [];

  const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const parsed = new URL(rawUrl, 'http://localhost');
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    const headers = normalizeHeaders(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    const body = parseBody(init?.body);

    const call: RecordedCall = {
      method,
      url: rawUrl,
      pathname: parsed.pathname,
      searchParams: parsed.searchParams,
      headers,
      body,
    };
    calls.push(call);

    for (const override of overrides) {
      if (matchesOverride(override, call)) {
        if (MUTATING_METHODS.has(method)) {
          const ct = call.headers['content-type'] ?? '';
          if (!ct.toLowerCase().includes('application/json')) {
            return toResponse({
              status: 415,
              body: { error: 'Unsupported Media Type: expected application/json' },
            });
          }
        }
        return toResponse(await override.handler(call));
      }
    }

    return toResponse(defaultResponse(call));
  });

  vi.stubGlobal('fetch', fetchSpy);

  return {
    calls,
    callsFor(method: string, pathPart: string | RegExp) {
      const m = method.toUpperCase();
      return calls.filter((c) => {
        if (c.method !== m) return false;
        if (typeof pathPart === 'string') return c.url.includes(pathPart);
        return pathPart.test(c.url);
      });
    },
    clearCalls() {
      calls.splice(0, calls.length);
    },
  };
}
