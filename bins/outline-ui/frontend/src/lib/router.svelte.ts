export const route = $state({ path: typeof location !== 'undefined' ? location.pathname : '/' });
export function go(path: string) { history.pushState({}, '', path); route.path = path; }
if (typeof window !== 'undefined') window.addEventListener('popstate', () => { route.path = location.pathname; });
export function section(path = route.path): 'ss'|'ws'|'landing' {
  if (path.startsWith('/ss')) return 'ss';
  if (path.startsWith('/ws')) return 'ws';
  return 'landing';
}
