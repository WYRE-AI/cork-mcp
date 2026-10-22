/**
 * HTTP transport fails closed (CWE-306).
 *
 * Startup refuses to listen when CONDUIT_S2S_SECRET is empty or a known
 * placeholder, unless MCP_ALLOW_INSECURE_DEV=1 (empty secret only). That
 * bypass binds 127.0.0.1 only. Gateway-mode /mcp requests without
 * X-Cork-Api-Key are 401 and must not consult process.env credentials.
 */
import type { Server } from 'node:net';
import { createHmac } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

const whoAmIMock = vi.hoisted(() => vi.fn(async () => ({ id: 'header-user' })));
const getCredentialsSpy = vi.hoisted(() => vi.fn());

vi.mock('../client.js', async () => {
  const actual = await vi.importActual<typeof import('../client.js')>('../client.js');
  return {
    ...actual,
    whoAmI: whoAmIMock,
    getCredentials: () => {
      const creds = actual.getCredentials();
      getCredentialsSpy(creds);
      return creds;
    },
  };
});

import { startHttpServer } from '../http.js';

const TEST_SECRET = 'test-s2s-fail-closed-secret-do-not-use-in-prod';
const ENV_API_KEY = 'env-cork-key-must-not-be-used';
const HEADER_API_KEY = 'header-cork-key';

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
  'CORK_API_KEY',
  'LOG_LEVEL',
] as const;

const originalEnv = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
const servers: Server[] = [];

function restoreEnv(): void {
  for (const key of ENV_KEYS) {
    const value = originalEnv[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac('sha256', secret).update(message).digest('hex');
  return `${message},v1=${hex}`;
}

function captureConsoleError(): { text: () => string; restore: () => void } {
  const lines: string[] = [];
  const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  return {
    text: () => lines.join('\n'),
    restore: () => spy.mockRestore(),
  };
}

function exitSpy() {
  return vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
}

async function listen(): Promise<{ port: number; address: string }> {
  const server = await startHttpServer();
  servers.push(server);
  const bound = server.address();
  if (!bound || typeof bound === 'string') {
    throw new Error('HTTP server did not bind a TCP port');
  }
  return { port: bound.port, address: bound.address };
}

function mcpHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  };
}

const whoCall = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: { name: 'cork_who_am_i', arguments: {} },
});

async function postMcp(port: number, headers: Record<string, string>): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}/mcp`, {
    method: 'POST',
    headers: mcpHeaders(headers),
    body: whoCall,
  });
}

afterEach(async () => {
  restoreEnv();
  whoAmIMock.mockClear();
  getCredentialsSpy.mockClear();
  const open = servers.splice(0);
  await Promise.all(
    open.map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          if (!server.listening) {
            resolve();
            return;
          }
          server.close((err) => (err ? reject(err) : resolve()));
        })
    )
  );
});

describe('HTTP startup fails closed without CONDUIT_S2S_SECRET', () => {
  it('logs an error and exits non-zero when the secret is empty', async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.MCP_HTTP_PORT = '0';
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.LOG_LEVEL = 'error';
    process.env.CORK_API_KEY = ENV_API_KEY;

    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      const logged = captured.text();
      expect(logged).toContain('Refusing to start HTTP server: CONDUIT_S2S_SECRET is empty.');
      expect(logged).toContain('MCP_ALLOW_INSECURE_DEV=1');
      expect(logged).not.toContain(TEST_SECRET);
      expect(logged).not.toContain(ENV_API_KEY);
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('treats a whitespace-only secret as empty', async () => {
    process.env.CONDUIT_S2S_SECRET = '   ';
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.MCP_HTTP_PORT = '0';
    process.env.LOG_LEVEL = 'error';

    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(captured.text()).toContain('CONDUIT_S2S_SECRET is empty.');
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('still exits when MCP_ALLOW_INSECURE_DEV is not exactly 1', async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    process.env.MCP_ALLOW_INSECURE_DEV = 'true';
    process.env.MCP_HTTP_PORT = '0';
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.LOG_LEVEL = 'error';

    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      expect(captured.text()).toContain('Refusing to start HTTP server');
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('starts and logs a warning when MCP_ALLOW_INSECURE_DEV=1 and binds 127.0.0.1', async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    delete process.env.MCP_HTTP_HOST;
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.LOG_LEVEL = 'error';
    process.env.CORK_API_KEY = ENV_API_KEY;

    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      const server = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe('127.0.0.1');
      const logged = captured.text();
      expect(logged).toContain('SECURITY WARNING');
      expect(logged).toContain('MCP_ALLOW_INSECURE_DEV=1');
      expect(logged).toContain('DISABLED');
      expect(logged).toContain('127.0.0.1');
      expect(logged).not.toContain(TEST_SECRET);
      expect(logged).not.toContain(ENV_API_KEY);
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it.each(['replace-with-a-real-secret', 'changeme', '  Your-S2S-Secret  '])(
    'refuses known placeholder %j and does not log it',
    async (placeholder) => {
      process.env.CONDUIT_S2S_SECRET = placeholder;
      delete process.env.MCP_ALLOW_INSECURE_DEV;
      process.env.MCP_HTTP_PORT = '0';
      process.env.MCP_HTTP_HOST = '127.0.0.1';
      process.env.LOG_LEVEL = 'error';

      const captured = captureConsoleError();
      const exit = exitSpy();
      try {
        await expect(startHttpServer()).rejects.toThrow('process.exit:1');
        expect(exit).toHaveBeenCalledWith(1);
        const logged = captured.text();
        expect(logged).toContain('known placeholder');
        expect(logged).toContain('openssl rand -hex 32');
        expect(logged).not.toContain(placeholder.trim());
        expect(logged).not.toContain(TEST_SECRET);
      } finally {
        captured.restore();
        exit.mockRestore();
      }
    }
  );

  it('refuses a placeholder even when MCP_ALLOW_INSECURE_DEV=1', async () => {
    process.env.CONDUIT_S2S_SECRET = '  Your-S2S-Secret  ';
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.LOG_LEVEL = 'error';

    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      await expect(startHttpServer()).rejects.toThrow('process.exit:1');
      expect(exit).toHaveBeenCalledWith(1);
      expect(captured.text()).toContain('known placeholder');
      expect(captured.text()).not.toContain('Your-S2S-Secret');
      expect(captured.text()).not.toContain('SECURITY WARNING');
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('forces 127.0.0.1 when insecure dev is set and the host is loopback', async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.MCP_HTTP_HOST = 'localhost';
    process.env.LOG_LEVEL = 'info';

    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      const server = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe('127.0.0.1');
      expect(captured.text()).toContain('listening on 127.0.0.1:');
      expect(captured.text()).not.toContain('listening on localhost');
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it.each(['0.0.0.0', '10.1.2.3'])(
    'refuses insecure dev when MCP_HTTP_HOST is %s',
    async (host) => {
      delete process.env.CONDUIT_S2S_SECRET;
      process.env.MCP_ALLOW_INSECURE_DEV = '1';
      process.env.MCP_HTTP_PORT = '0';
      process.env.MCP_HTTP_HOST = host;
      process.env.LOG_LEVEL = 'error';

      const captured = captureConsoleError();
      const exit = exitSpy();
      try {
        await expect(startHttpServer()).rejects.toThrow('process.exit:1');
        expect(exit).toHaveBeenCalledWith(1);
        const logged = captured.text();
        expect(logged).toContain('only binds 127.0.0.1');
        expect(logged).toContain(`MCP_HTTP_HOST=${host}`);
        expect(logged).not.toContain('SECURITY WARNING');
        expect(logged).not.toContain(TEST_SECRET);
      } finally {
        captured.restore();
        exit.mockRestore();
      }
    }
  );

  it('honors a non-loopback host when a real secret is set', async () => {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.MCP_HTTP_PORT = '0';
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    process.env.MCP_TRUSTED_TLS_INGRESS = '1';
    process.env.LOG_LEVEL = 'info';

    const captured = captureConsoleError();
    const exit = exitSpy();
    try {
      const server = await listen();
      expect(exit).not.toHaveBeenCalled();
      expect(server.address).toBe('0.0.0.0');
      const logged = captured.text();
      expect(logged).toContain('listening on 0.0.0.0:');
      expect(logged).not.toContain(TEST_SECRET);
    } finally {
      captured.restore();
      exit.mockRestore();
    }
  });

  it('defaults to 127.0.0.1 when a real secret is set and MCP_HTTP_HOST is unset', async () => {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    delete process.env.MCP_HTTP_HOST;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.MCP_HTTP_PORT = '0';
    process.env.LOG_LEVEL = 'info';

    const captured = captureConsoleError();
    try {
      const server = await listen();
      expect(server.address).toBe('127.0.0.1');
      expect(captured.text()).toContain('listening on 127.0.0.1:');
      expect(captured.text()).not.toContain(TEST_SECRET);
    } finally {
      captured.restore();
    }
  });
});

describe('gateway /mcp auth', () => {
  async function gatewayServer(): Promise<number> {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.AUTH_MODE = 'gateway';
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.CORK_API_KEY = ENV_API_KEY;
    process.env.LOG_LEVEL = 'error';
    const server = await listen();
    return server.port;
  }

  it('serves /health without authentication and without reading credentials', async () => {
    const port = await gatewayServer();
    getCredentialsSpy.mockClear();
    whoAmIMock.mockClear();

    const res = await fetch(`http://127.0.0.1:${port}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status?: string; mode?: string; credentials?: unknown };
    expect(body.status).toBe('ok');
    expect(body.mode).toBe('gateway');
    expect(body.credentials).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain(ENV_API_KEY);
    expect(JSON.stringify(body)).not.toContain(TEST_SECRET);
    expect(getCredentialsSpy).not.toHaveBeenCalled();
    expect(whoAmIMock).not.toHaveBeenCalled();
  });

  it('returns 401 when the S2S header is missing or invalid and does not read credentials', async () => {
    const port = await gatewayServer();
    getCredentialsSpy.mockClear();

    const missing = await postMcp(port, { 'x-cork-api-key': HEADER_API_KEY });
    const invalid = await postMcp(port, {
      'x-gateway-s2s': mintS2sHeader('wrong-secret'),
      'x-cork-api-key': HEADER_API_KEY,
    });

    expect(missing.status).toBe(401);
    expect(invalid.status).toBe(401);
    const missingBody = await missing.json();
    const invalidBody = await invalid.json();
    expect(missingBody.error).toMatch(/X-Gateway-S2S/);
    expect(invalidBody.error).toMatch(/X-Gateway-S2S/);
    expect(JSON.stringify(missingBody)).not.toContain(ENV_API_KEY);
    expect(JSON.stringify(missingBody)).not.toContain(TEST_SECRET);
    expect(JSON.stringify(invalidBody)).not.toContain(HEADER_API_KEY);
    expect(getCredentialsSpy).not.toHaveBeenCalled();
    expect(whoAmIMock).not.toHaveBeenCalled();
  });

  it('returns 401 in gateway mode without a credential header and does not use env credentials', async () => {
    const port = await gatewayServer();
    getCredentialsSpy.mockClear();

    const missing = await postMcp(port, { 'x-gateway-s2s': mintS2sHeader(TEST_SECRET) });
    const blank = await postMcp(port, {
      'x-gateway-s2s': mintS2sHeader(TEST_SECRET),
      'x-cork-api-key': '   ',
    });

    expect(missing.status).toBe(401);
    expect(blank.status).toBe(401);
    const body = await missing.json();
    expect(body.error).toMatch(/X-Cork-Api-Key/);
    expect(body.error).toMatch(/credential header/i);
    expect(JSON.stringify(body)).not.toContain(ENV_API_KEY);
    expect(JSON.stringify(body)).not.toContain(TEST_SECRET);
    expect(getCredentialsSpy).not.toHaveBeenCalled();
    expect(whoAmIMock).not.toHaveBeenCalled();
  });

  it('accepts a valid S2S header plus X-Cork-Api-Key and uses that credential', async () => {
    const port = await gatewayServer();
    getCredentialsSpy.mockClear();
    whoAmIMock.mockClear();

    const res = await postMcp(port, {
      'x-gateway-s2s': mintS2sHeader(TEST_SECRET),
      'x-cork-api-key': HEADER_API_KEY,
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { result?: { content?: Array<{ text?: string }> } };
    const text = body.result?.content?.[0]?.text ?? '';
    expect(JSON.parse(text)).toEqual({ id: 'header-user' });
    expect(JSON.stringify(body)).not.toContain(ENV_API_KEY);
    expect(JSON.stringify(body)).not.toContain(TEST_SECRET);
    expect(whoAmIMock).toHaveBeenCalledWith({ apiKey: HEADER_API_KEY });
    const reads = getCredentialsSpy.mock.calls.map((call) => call[0]);
    expect(reads).toContainEqual({ apiKey: HEADER_API_KEY });
    expect(JSON.stringify(reads)).not.toContain(ENV_API_KEY);
  });
});

describe('env-mode HTTP still requires S2S and uses CORK_API_KEY', () => {
  it('returns 401 without S2S and does not fall through to the API key', async () => {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    delete process.env.AUTH_MODE;
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.CORK_API_KEY = ENV_API_KEY;
    process.env.LOG_LEVEL = 'error';
    const { port } = await listen();
    getCredentialsSpy.mockClear();

    const res = await postMcp(port, {});
    expect(res.status).toBe(401);
    expect(getCredentialsSpy).not.toHaveBeenCalled();
    expect(whoAmIMock).not.toHaveBeenCalled();
  });

  it('uses the env API key after a valid S2S header when AUTH_MODE is not gateway', async () => {
    process.env.CONDUIT_S2S_SECRET = TEST_SECRET;
    delete process.env.AUTH_MODE;
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.CORK_API_KEY = ENV_API_KEY;
    process.env.LOG_LEVEL = 'error';
    const { port } = await listen();
    getCredentialsSpy.mockClear();
    whoAmIMock.mockClear();

    const res = await postMcp(port, { 'x-gateway-s2s': mintS2sHeader(TEST_SECRET) });
    expect(res.status).toBe(200);
    expect(whoAmIMock).toHaveBeenCalledWith({ apiKey: ENV_API_KEY });
  });
});
