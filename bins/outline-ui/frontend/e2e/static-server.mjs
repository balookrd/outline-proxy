import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const distDir = path.resolve(import.meta.dirname, '..', 'dist');
const indexHtmlPath = path.join(distDir, 'index.html');

if (!fs.existsSync(indexHtmlPath)) {
  console.error(`Missing ${indexHtmlPath}. Run "pnpm build" first.`);
  process.exit(1);
}

const port = Number(process.env.E2E_PORT || 4173);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; style-src 'self' 'unsafe-inline'; script-src 'self'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

function sendFile(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_TYPES[ext] ?? 'application/octet-stream';
  const body = fs.readFileSync(filePath);
  res.writeHead(200, {
    ...SECURITY_HEADERS,
    'Content-Type': mime,
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
  const pathname = decodeURIComponent(reqUrl.pathname);

  if (
    pathname === '/api/meta' ||
    pathname.startsWith('/api/') ||
    pathname.startsWith('/ss/dashboard/api/') ||
    pathname.startsWith('/ws/dashboard/api/')
  ) {
    res.writeHead(501, {
      ...SECURITY_HEADERS,
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify({ error: `unmocked api route: ${req.method} ${pathname}` }));
    return;
  }

  if (pathname.startsWith('/ui-assets/')) {
    const rel = pathname.slice('/ui-assets/'.length);
    const resolved = path.resolve(distDir, rel);
    if (
      resolved.startsWith(distDir + path.sep) &&
      fs.existsSync(resolved) &&
      fs.statSync(resolved).isFile()
    ) {
      sendFile(res, resolved);
      return;
    }
    res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found\n');
    return;
  }

  if (
    pathname === '/favicon.png' ||
    pathname === '/favicon-dark.png' ||
    pathname === '/favicon-light.png'
  ) {
    const iconPath = path.join(distDir, pathname.slice(1));
    if (fs.existsSync(iconPath) && fs.statSync(iconPath).isFile()) {
      sendFile(res, iconPath);
      return;
    }
  }

  sendFile(res, indexHtmlPath);
});

server.listen(port, '127.0.0.1', () => {
  console.log(`outline-ui e2e static server listening on http://127.0.0.1:${port}`);
});
