import { createServer as createHttpServer, type Server } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import { runWithCredentials } from './client.js';
import { logger } from './utils/logger.js';
import { verifyS2sHeader, S2S_HEADER } from './s2s-verify.js';

// Conduit service-to-service auth (gateway#377 parity). HTTP startup fails
// closed. An empty CONDUIT_S2S_SECRET refuses to boot unless
// MCP_ALLOW_INSECURE_DEV=1, and that bypass binds 127.0.0.1 only. A known
// placeholder secret always refuses to start, even with that flag. When a
// real secret is set, every /mcp request must carry a valid X-Gateway-S2S
// header and MCP_HTTP_HOST is honored. The secret value is never logged.
// Read at startup, not at module load, so tests can exercise each branch.

const KNOWN_PLACEHOLDER_SECRETS = new Set([
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
]);

const MISSING_S2S_SECRET_ERROR =
  'Refusing to start HTTP server: CONDUIT_S2S_SECRET is empty. ' +
  'Set CONDUIT_S2S_SECRET to the gateway-provisioned secret (openssl rand -hex 32), or set MCP_ALLOW_INSECURE_DEV=1 for local development only.';

const PLACEHOLDER_S2S_SECRET_ERROR =
  'Refusing to start HTTP server: CONDUIT_S2S_SECRET is a known placeholder. ' +
  'Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value.';

const INSECURE_DEV_WARNING =
  'SECURITY WARNING: CONDUIT_S2S_SECRET is unset and MCP_ALLOW_INSECURE_DEV=1. ' +
  'HTTP /mcp is starting with service-to-service authentication DISABLED, bound to 127.0.0.1 only. ' +
  'Local development only; do not expose this port.';

const INSECURE_DEV_NON_LOOPBACK_ERROR =
  'Refusing to start HTTP server: MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET only binds 127.0.0.1. ' +
  'Unset MCP_HTTP_HOST or set it to 127.0.0.1.';

const LOOPBACK_HOST = '127.0.0.1';

const S2S_UNAUTHORIZED = {
  error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
};

const GATEWAY_CREDENTIALS_UNAUTHORIZED = {
  error: 'Unauthorized: missing required gateway credential header X-Cork-Api-Key.',
};

function readS2sSecret(): { secret: string; isPlaceholder: boolean } {
  const raw = (process.env.CONDUIT_S2S_SECRET ?? '').trim();
  const isPlaceholder = KNOWN_PLACEHOLDER_SECRETS.has(raw.toLowerCase());
  return { secret: isPlaceholder ? '' : raw, isPlaceholder };
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  if (normalized === 'localhost' || normalized === '::1' || normalized === '[::1]') return true;
  const bare = normalized.startsWith('::ffff:') ? normalized.slice('::ffff:'.length) : normalized;
  const parts = bare.split('.');
  if (parts.length !== 4) return false;
  if (parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return false;
  return parts[0] === '127';
}

/** True when startup is the insecure-dev bypass (no real secret). */
function enforceS2sSecretOrExit(secret: string, isPlaceholder: boolean): boolean {
  if (isPlaceholder) {
    logger.error(PLACEHOLDER_S2S_SECRET_ERROR);
    process.exit(1);
  }
  if (secret) return false;
  if (process.env.MCP_ALLOW_INSECURE_DEV === '1') return true;
  logger.error(MISSING_S2S_SECRET_ERROR);
  process.exit(1);
}

/**
 * No secret: bind 127.0.0.1 only. A non-loopback MCP_HTTP_HOST is refused.
 * A configured secret honors MCP_HTTP_HOST, and defaults to 127.0.0.1 when
 * that variable is unset.
 */
function resolveBindHost(insecureDev: boolean): string {
  const configured = (process.env.MCP_HTTP_HOST ?? '').trim();
  if (!insecureDev) {
    return configured === '' ? LOOPBACK_HOST : configured;
  }
  if (configured === '' || isLoopbackHost(configured)) return LOOPBACK_HOST;
  logger.error(`${INSECURE_DEV_NON_LOOPBACK_ERROR} MCP_HTTP_HOST=${configured} is not loopback.`);
  process.exit(1);
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && typeof value[0] === 'string') return value[0];
  return undefined;
}

function credentialHeader(value: string | string[] | undefined): string | undefined {
  const raw = singleHeader(value);
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Start the Cork MCP Streamable HTTP server.
 *
 * Fails closed: a missing or blank CONDUIT_S2S_SECRET logs an error and calls
 * process.exit(1) before anything listens. MCP_ALLOW_INSECURE_DEV=1 bypasses
 * only a missing or blank secret: it skips X-Gateway-S2S and binds 127.0.0.1
 * only. A placeholder or otherwise unusable secret always exits, with or
 * without that flag. With a secret, every /mcp request must carry a valid
 * X-Gateway-S2S header; /health stays unauthenticated.
 *
 * @returns The listening `Server`, once `listen` has succeeded.
 * @throws Rejects with the bind error (for example EADDRINUSE or EACCES) if
 *   the port cannot be bound.
 */
export async function startHttpServer(): Promise<Server> {
  const { secret, isPlaceholder } = readS2sSecret();
  const insecureDev = enforceS2sSecretOrExit(secret, isPlaceholder);

  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const host = resolveBindHost(insecureDev);
  if (insecureDev) {
    // error level so LOG_LEVEL=warn|error cannot hide the bypass. Logged
    // only after the loopback check, so a refused public bind does not
    // claim the server is starting.
    logger.error(INSECURE_DEV_WARNING);
  }
  const isGatewayMode = process.env.AUTH_MODE === 'gateway';

  const httpServer = createHttpServer(async (req, res) => {
    // Fixed base: a malformed Host header must not throw before auth.
    let url: URL;
    try {
      url = new URL(req.url || '/', 'http://localhost');
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad request' }));
      return;
    }

    // /health is container liveness, not credential readiness. Always 200
    // while the process is up. Must not read vendor credentials: this route
    // is unauthenticated, and gateway mode has no process-level API key.
    if (url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          transport: 'http',
          mode: isGatewayMode ? 'gateway' : 'standalone',
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health'] }));
      return;
    }

    // Rejected before any credential extraction. Empty secret is only
    // reachable when MCP_ALLOW_INSECURE_DEV=1; startup refuses otherwise.
    if (secret && !verifyS2sHeader(singleHeader(req.headers[S2S_HEADER]), secret)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(S2S_UNAUTHORIZED));
      return;
    }

    // node:http does not await this listener. Catch a rejected connect or
    // handleRequest so one bad request cannot crash the process. The log
    // stays generic because error text can echo tenant credentials.
    const fail = (error: unknown): void => {
      logger.error('MCP request failed', { errorName: error instanceof Error ? error.name : typeof error });
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
      if (!res.writableEnded) res.end(JSON.stringify({ error: 'Internal server error' }));
    };

    const handle = async () => {
      // SECURITY-CRITICAL invariant: this transport MUST stay stateless
      // (sessionIdGenerator: undefined + enableJsonResponse: true).
      // Per-request tenant credentials are carried in an AsyncLocalStorage
      // context opened by runWithCredentials() below. A stateless
      // request->single-response flow keeps the tool call inside that
      // context - switching to a stateful/SSE transport would let a
      // long-lived connection serve later messages under a stale/foreign
      // credential context.
      const server = createServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    };

    if (isGatewayMode) {
      const apiKey = credentialHeader(req.headers['x-cork-api-key']);
      if (!apiKey) {
        // Do not fall through to process.env. In gateway mode that would let
        // any caller who reached this process use the container's CORK_API_KEY.
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(GATEWAY_CREDENTIALS_UNAUTHORIZED));
        return;
      }
      await runWithCredentials({ apiKey }, handle).catch(fail);
      return;
    }

    await handle().catch(fail);
  });

  return new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(port, host, () => {
      const bound = httpServer.address();
      const shown =
        typeof bound === 'object' && bound ? `${bound.address}:${bound.port}` : `${host}:${port}`;
      logger.info(`HTTP streaming server listening on ${shown}`);
      resolve(httpServer);
    });
  });
}

if (process.env.VITEST !== 'true') {
  const transport = process.env.MCP_TRANSPORT;
  if (transport === 'http') {
    void startHttpServer().catch((error: unknown) => {
      logger.error('Fatal HTTP startup error', {
        error: error instanceof Error ? error.message : String(error),
      });
      process.exit(1);
    });
  } else {
    void import('./index.js');
  }
}
