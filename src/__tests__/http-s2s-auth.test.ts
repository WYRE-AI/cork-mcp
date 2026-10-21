/**
 * HTTP transport fail-closed auth (CWE-306; WYREAI-454).
 *
 * Startup requires a real CONDUIT_S2S_SECRET unless MCP_ALLOW_INSECURE_DEV=1
 * (loopback only). Known placeholders never count. /mcp rejects a missing or
 * invalid X-Gateway-S2S header; /health stays unauthenticated.
 */

import { createHmac } from 'node:crypto';
import { request as httpRequest, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { startHttpServer } from '../http.js';

const S2S_SECRET = 's2s-do-not-log-7f3a';

const PLACEHOLDERS = [
  'replace-with-a-real-secret',
  'your-s2s-secret',
  'your-secret',
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'example',
  'replace-me',
  's2s-secret',
] as const;

const ENV_KEYS = [
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'AUTH_MODE',
  'CORK_API_KEY',
  'LOG_LEVEL',
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: Server[] = [];

function mintS2sHeader(secret: string): string {
  const message = `t=${Math.floor(Date.now() / 1000)}`;
  return `${message},v1=${createHmac('sha256', secret).update(message).digest('hex')}`;
}

function captureStderr(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
  });
  return { text: () => lines.join('\n'), restore: () => spy.mockRestore() };
}

function send(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: string) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = httpRequest({ hostname: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(5000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

async function listen(): Promise<{ port: number; address: string }> {
  const server = await startHttpServer();
  servers.push(server);
  const bound = server.address() as AddressInfo;
  return { port: bound.port, address: bound.address };
}

const mcpHeaders = (extra: Record<string, string> = {}) => ({
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
  ...extra,
});

const initialize = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } },
});

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  process.env.MCP_HTTP_PORT = '0';
  process.env.MCP_HTTP_HOST = '127.0.0.1';
  process.env.LOG_LEVEL = 'info';
  process.env.AUTH_MODE = 'env';
  process.env.CORK_API_KEY = 'k';
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
});

afterEach(async () => {
  vi.restoreAllMocks();
  while (servers.length > 0) {
    const server = servers.pop()!;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

describe('HTTP startup', () => {
  it('rejects when CONDUIT_S2S_SECRET is empty', async () => {
    await expect(startHttpServer()).rejects.toThrow(
      /Refusing to start HTTP transport: CONDUIT_S2S_SECRET is empty/,
    );
  });

  it('rejects a whitespace-only secret, and MCP_ALLOW_INSECURE_DEV that is not exactly 1', async () => {
    process.env.CONDUIT_S2S_SECRET = '   ';
    process.env.MCP_ALLOW_INSECURE_DEV = 'true';
    await expect(startHttpServer()).rejects.toThrow(/CONDUIT_S2S_SECRET is empty/);
  });

  it.each(PLACEHOLDERS)('rejects known placeholder %j (even with the dev flag) and does not log it', async (p) => {
    process.env.CONDUIT_S2S_SECRET = `  ${p.toUpperCase()}  `;
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    const logs = captureStderr();
    try {
      await expect(startHttpServer()).rejects.toThrow(/known placeholder/);
      expect(logs.text()).not.toContain(p);
    } finally {
      logs.restore();
    }
  });

  it('starts on loopback with a warning when MCP_ALLOW_INSECURE_DEV=1 and the secret is empty', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    delete process.env.MCP_HTTP_HOST;
    const logs = captureStderr();
    try {
      const server = await listen();
      expect(server.address).toBe('127.0.0.1');
      expect(logs.text()).toContain('SECURITY WARNING');
      expect(logs.text()).toContain('MCP_ALLOW_INSECURE_DEV');
    } finally {
      logs.restore();
    }
  });

  it('does not S2S-gate /mcp in insecure dev mode', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    const logs = captureStderr();
    try {
      const server = await listen();
      const res = await send(server.port, 'POST', '/mcp', mcpHeaders(), initialize);
      expect(res.status).not.toBe(401);
    } finally {
      logs.restore();
    }
  });

  it.each(['0.0.0.0', '10.1.2.3'])('rejects insecure dev with non-loopback MCP_HTTP_HOST=%s', async (host) => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_HOST = host;
    const logs = captureStderr();
    try {
      await expect(startHttpServer()).rejects.toThrow(/limited to loopback/);
    } finally {
      logs.restore();
    }
  });

  it('honors MCP_HTTP_HOST and defaults to 0.0.0.0 when a secret is configured', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    delete process.env.MCP_HTTP_HOST;
    expect((await listen()).address).toBe('0.0.0.0');
  });
});

describe('HTTP /mcp authentication', () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
  });

  it('returns 401 for a missing or invalid S2S header without logging the secret', async () => {
    const logs = captureStderr();
    try {
      const server = await listen();
      const missing = await send(server.port, 'POST', '/mcp', mcpHeaders(), initialize);
      const invalid = await send(
        server.port,
        'POST',
        '/mcp',
        mcpHeaders({ 'x-gateway-s2s': mintS2sHeader('wrong-secret') }),
        initialize,
      );
      expect(missing.status).toBe(401);
      expect(invalid.status).toBe(401);
      expect(missing.body).toContain('X-Gateway-S2S');
      expect(logs.text()).not.toContain(S2S_SECRET);
    } finally {
      logs.restore();
    }
  });

  it('accepts a valid S2S header', async () => {
    const server = await listen();
    const res = await send(
      server.port,
      'POST',
      '/mcp',
      mcpHeaders({ 'x-gateway-s2s': mintS2sHeader(S2S_SECRET) }),
      initialize,
    );
    expect(res.status).toBe(200);
    expect(res.body).not.toContain(S2S_SECRET);
  });

  it('serves /health without authentication', async () => {
    const server = await listen();
    const res = await send(server.port, 'GET', '/health');
    expect(res.status).toBe(200);
    expect(res.body).not.toContain(S2S_SECRET);
  });
});
