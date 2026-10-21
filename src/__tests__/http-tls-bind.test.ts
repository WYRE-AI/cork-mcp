/**
 * HTTP transport enforces TLS-or-loopback (CWE-319).
 *
 * After the S2S fail-closed check and host resolution, a non-loopback bind
 * needs MCP_TLS_CERT_FILE + MCP_TLS_KEY_FILE (HTTPS) or
 * MCP_TRUSTED_TLS_INGRESS=1 (plain HTTP with a warning). Anything else exits.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest, type Server as HttpsServer } from 'node:https';
import type { Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { isLoopbackHost, startHttpServer } from '../http.js';

const TEST_SECRET = 'test-s2s-tls-bind-secret-do-not-use-in-prod';

const ENV_KEYS = [
  'MCP_TRANSPORT',
  'AUTH_MODE',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_TRUSTED_TLS_INGRESS',
  'MCP_TLS_CERT_FILE',
  'MCP_TLS_KEY_FILE',
  'LOG_LEVEL',
] as const;

const originalEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
const servers: Server[] = [];

function baseEnv(host: string): void {
  for (const key of ENV_KEYS) delete process.env[key];
  process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
  process.env.MCP_HTTP_PORT = '0';
  process.env.MCP_HTTP_HOST = host;
  process.env.LOG_LEVEL = 'info';
}

function captureConsoleError(): { text: () => string; lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  return { text: () => lines.join('\n'), lines, restore: () => spy.mockRestore() };
}

function exitSpy() {
  return vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
}

async function listen(): Promise<{ server: Server; port: number }> {
  const server = await startHttpServer();
  servers.push(server);
  const bound = server.address();
  if (!bound || typeof bound === 'string') throw new Error('server did not bind a TCP port');
  return { server, port: bound.port };
}

let opensslDir: string | undefined;
let certFile = '';
let keyFile = '';
let opensslSkipReason: string | undefined;

beforeAll(() => {
  try {
    opensslDir = mkdtempSync(join(tmpdir(), 'cork-mcp-tls-'));
    certFile = join(opensslDir, 'cert.pem');
    keyFile = join(opensslDir, 'key.pem');
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-days', '1', '-keyout', keyFile, '-out', certFile],
      { stdio: 'ignore' }
    );
  } catch {
    opensslSkipReason = 'openssl is unavailable, cannot generate a throwaway certificate';
  }
});

afterAll(() => {
  if (opensslDir) rmSync(opensslDir, { recursive: true, force: true });
});

afterEach(async () => {
  for (const key of ENV_KEYS) {
    const value = originalEnv[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  const open = servers.splice(0);
  await Promise.all(
    open.map(
      (server) =>
        new Promise<void>((resolve) => {
          if (!server.listening) return resolve();
          server.close(() => resolve());
          (server as { closeAllConnections?: () => void }).closeAllConnections?.();
        })
    )
  );
});

describe('isLoopbackHost', () => {
  it.each(['127.0.0.1', '127.1.2.3', '::1', '[::1]', 'localhost', 'LOCALHOST', ' localhost '])(
    'treats %j as loopback',
    (host) => expect(isLoopbackHost(host)).toBe(true)
  );
  it.each(['0.0.0.0', '::', '10.0.0.5', '128.0.0.1', 'example.com', ''])(
    'treats %j as non-loopback',
    (host) => expect(isLoopbackHost(host)).toBe(false)
  );
});

describe('HTTP transport TLS-or-loopback', () => {
  it('starts plain HTTP on loopback with no flag and no TLS files', async () => {
    baseEnv('127.0.0.1');
    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      const { server } = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect((server as unknown as HttpsServer).setSecureContext).toBeUndefined();
      expect(captured.text()).toContain('(http)');
      expect(captured.text()).not.toContain('SECURITY WARNING');
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('refuses a non-loopback bind without TLS files or the ingress flag', async () => {
    baseEnv('0.0.0.0');
    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      expect(captured.text()).toContain('MCP_TRUSTED_TLS_INGRESS');
      expect(captured.text()).toContain('CWE-319');
      expect(captured.text()).not.toContain('listening on');
      expect(captured.text()).not.toContain(TEST_SECRET);
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('does not accept MCP_TRUSTED_TLS_INGRESS values other than exactly 1', async () => {
    baseEnv('0.0.0.0');
    process.env.MCP_TRUSTED_TLS_INGRESS = 'true';
    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('starts plain HTTP behind a trusted ingress and logs exactly one warning', async () => {
    baseEnv('0.0.0.0');
    process.env.MCP_TRUSTED_TLS_INGRESS = '1';
    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await listen();
      expect(exit).not.toHaveBeenCalled();
      const warnings = captured.lines.filter((line) => line.includes('MCP_TRUSTED_TLS_INGRESS'));
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain('SECURITY WARNING');
      expect(captured.text()).not.toContain(TEST_SECRET);
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('refuses when only one of the TLS variables is set', async () => {
    for (const [name, missing] of [
      ['MCP_TLS_CERT_FILE', 'MCP_TLS_KEY_FILE'],
      ['MCP_TLS_KEY_FILE', 'MCP_TLS_CERT_FILE'],
    ] as const) {
      baseEnv('127.0.0.1');
      process.env[name] = '/nonexistent/file.pem';
      const captured = captureConsoleError();
      const exit = exitSpy();
      try {
        await expect(startHttpServer()).rejects.toThrow('process.exit:1');
        expect(exit).toHaveBeenCalledWith(1);
        expect(captured.text()).toContain(`${missing} is not set`);
      } finally {
        captured.restore();
        exit.mockRestore();
      }
    }
  });

  it('refuses when a TLS file cannot be read, logging only path and code', async () => {
    baseEnv('0.0.0.0');
    process.env.MCP_TLS_CERT_FILE = '/nonexistent/cert.pem';
    process.env.MCP_TLS_KEY_FILE = '/nonexistent/key.pem';
    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(captured.text()).toContain('ENOENT');
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('fires the S2S fail-closed error before the TLS check', async () => {
    baseEnv('0.0.0.0');
    process.env.CONDUIT_S2S_SECRET = '';
    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(captured.text()).toContain('CONDUIT_S2S_SECRET is empty.');
      expect(captured.text()).not.toContain('CWE-319');
      expect(captured.text()).not.toContain('MCP_TRUSTED_TLS_INGRESS');
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  describe('with TLS files', () => {
    function get(
      port: number,
      secure: boolean
    ): Promise<{ status: number | undefined }> {
      return new Promise((resolve, reject) => {
        const options = { host: '127.0.0.1', port, path: '/health', method: 'GET', rejectUnauthorized: false };
        const req = secure ? httpsRequest(options, done) : httpRequest(options, done);
        function done(res: { statusCode?: number; resume: () => void }) {
          res.resume();
          resolve({ status: res.statusCode });
        }
        req.on('error', reject);
        req.end();
      });
    }

    it.skipIf(opensslSkipReason !== undefined)(
      'serves HTTPS on a non-loopback bind and rejects plain HTTP',
      async () => {
        baseEnv('0.0.0.0');
        process.env.MCP_TLS_CERT_FILE = certFile;
        process.env.MCP_TLS_KEY_FILE = keyFile;
        const captured = captureConsoleError();
        const exit = exitSpy();
        try {
          const { server, port } = await listen();
          expect(exit).not.toHaveBeenCalled();
          expect(typeof (server as HttpsServer).setSecureContext).toBe('function');
          expect(captured.text()).toContain('TLS enabled');
          expect(captured.text()).toContain('(https)');
          expect(captured.text()).not.toContain('SECURITY WARNING');
          expect((await get(port, true)).status).toBe(200);
          await expect(get(port, false)).rejects.toBeDefined();
        } finally {
          captured.restore();
          exit.mockRestore();
        }
      }
    );

    it.skipIf(opensslSkipReason !== undefined)('also serves HTTPS on loopback', async () => {
      baseEnv('127.0.0.1');
      process.env.MCP_TLS_CERT_FILE = certFile;
      process.env.MCP_TLS_KEY_FILE = keyFile;
      const captured = captureConsoleError();
      try {
        const { port } = await listen();
        expect((await get(port, true)).status).toBe(200);
      } finally {
        captured.restore();
      }
    });
  });
});
