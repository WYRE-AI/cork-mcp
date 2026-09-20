import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleIntegrationTool, INTEGRATION_TOOLS } from '../tools/integrations.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleIntegrationTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // Hard scope boundary, scoped to this file specifically: this connector
  // must NEVER expose GET /integrations/{uuid}/credentials or GET
  // /integrations/{uuid}/raw-data, and must never expose the
  // connect/update/delete/resync writes.
  it('exposes exactly the 5 read-only integration tools', () => {
    const names = INTEGRATION_TOOLS.map((t) => t.name).sort();
    expect(names).toEqual([
      'cork_get_available_integrations',
      'cork_get_connected_integrations',
      'cork_get_integration_devices',
      'cork_get_integration_tenants',
      'cork_get_integration_users',
    ]);
  });

  it('cork_get_connected_integrations hits the connected-list endpoint, never credentials or raw-data', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ data: [{ uuid: 'i1', vendor: 'ninjaone', status: 'connected' }] })
    );

    const result = await runWithCredentials(creds, () =>
      handleIntegrationTool('cork_get_connected_integrations', {})
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/api/v1/integrations/connected');
    expect(result.isError).toBeUndefined();
  });

  it('cork_get_integration_devices scopes to the integration UUID and never touches /credentials or /raw-data', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [{ id: 'd1', hostname: 'ws-01' }] }));

    await runWithCredentials(creds, () =>
      handleIntegrationTool('cork_get_integration_devices', { integration_uuid: 'i1', tenant_uuid: 't1' })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/api/v1/integrations/i1/devices');
    expect(url.pathname).not.toMatch(/credentials|raw-data/);
    expect(url.searchParams.get('tenant_uuid')).toBe('t1');
  });

  it('rejects an unknown tool name rather than silently dispatching', async () => {
    const result = await runWithCredentials(creds, () =>
      handleIntegrationTool('cork_get_integration_credentials', {})
    );

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/Unknown tool/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
