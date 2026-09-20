import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleClientTool } from '../tools/clients.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleClientTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('cork_get_clients sends the Bearer token and forwards filters', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [{ uuid: 'c1', warranty_status: 'warranted' }] }));

    const result = await runWithCredentials(creds, () =>
      handleClientTool('cork_get_clients', { show_hidden: true, partner_uuid: 'p1' })
    );

    expect(result.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new URL(url).pathname).toBe('/api/v1/clients');
    expect(new URL(url).searchParams.get('show_hidden')).toBe('true');
    expect(new URL(url).searchParams.get('partner_uuid')).toBe('p1');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer key-1');
    expect(JSON.parse(textOf(result)).data[0].uuid).toBe('c1');
  });

  it('cork_get_client_devices scopes the request to the client UUID in the path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [{ id: 'd1', can_install_software: true }] }));

    const result = await runWithCredentials(creds, () =>
      handleClientTool('cork_get_client_devices', { client_uuid: 'c1' })
    );

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/api/v1/clients/c1/devices');
    expect(result.isError).toBeUndefined();
  });

  it('cork_get_client_score_history forwards created_after/created_before bounds', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] }));

    await runWithCredentials(creds, () =>
      handleClientTool('cork_get_client_score_history', {
        client_uuid: 'c1',
        created_after: '2026-01-01T00:00:00Z',
        created_before: '2026-03-31T23:59:59Z',
      })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/api/v1/clients/c1/score-history');
    expect(url.searchParams.get('created_after')).toBe('2026-01-01T00:00:00Z');
    expect(url.searchParams.get('created_before')).toBe('2026-03-31T23:59:59Z');
  });

  it('surfaces a 401 as a readable auth error rather than throwing', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'unauthorized' }, 401));

    const result = await runWithCredentials(creds, () =>
      handleClientTool('cork_get_clients', {})
    );

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/rejected the API key/i);
  });

  it('returns a credential error without calling fetch when no key is configured', async () => {
    const result = await handleClientTool('cork_get_clients', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/CORK_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
