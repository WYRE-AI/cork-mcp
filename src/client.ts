import { AsyncLocalStorage } from 'node:async_hooks';
import { logger } from './utils/logger.js';
import { CorkApiError, CorkAuthError, CorkRateLimitError } from './types.js';
import type {
  ClientScopedPageParams,
  CorkCredentials,
  CorkPagedResponse,
  GetAvailableIntegrationsParams,
  GetClientScoreHistoryParams,
  GetComplianceEventsParams,
  GetComplianceNotificationSettingsParams,
  GetConnectedIntegrationsParams,
  GetInstallerHistoryParams,
  GetInstallerSetupParams,
  GetSoftwarePackagesParams,
  GetSoftwareVulnerabilitiesParams,
  GetSoftwareVulnerabilitySummaryParams,
  IntegrationScopedPageParams,
  ListClientsParams,
  ListInvoicesParams,
  ListWarrantiesParams,
  PageParams,
} from './types.js';

export const BASE_URL = 'https://api.corkinc.com/api/v1';

// Request-scoped credential store. In gateway mode the HTTP layer runs each
// request inside runWithCredentials({apiKey}); getCredentials() reads from
// it. Falls back to process.env for stdio/single-tenant mode.
const credStore = new AsyncLocalStorage<CorkCredentials>();

export function runWithCredentials<T>(creds: CorkCredentials, fn: () => T): T {
  return credStore.run(creds, fn);
}

export function getCredentials(): CorkCredentials | null {
  const scoped = credStore.getStore();
  if (scoped?.apiKey) return scoped;
  const apiKey = process.env.CORK_API_KEY;
  if (!apiKey) {
    logger.warn('Missing credentials', { hasApiKey: !!apiKey });
    return null;
  }
  return { apiKey };
}

function buildQuery(params: Record<string, unknown> = {}): URLSearchParams {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    qs.append(key, String(value));
  }
  return qs;
}

async function doGet<T>(
  creds: CorkCredentials,
  path: string,
  query?: Record<string, unknown>
): Promise<T> {
  const qs = query ? buildQuery(query).toString() : '';
  const url = `${BASE_URL}${path}${qs ? `?${qs}` : ''}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${creds.apiKey}`, Accept: 'application/json' },
    signal: AbortSignal.timeout(15_000),
  });

  // 401 (invalid/revoked API key) and 429 (rate-limited) are distinct
  // failure modes with distinct remediations - grouping them under one
  // generic auth-error class hides a transient rate limit behind a message
  // that reads like a bad/expired key.
  if (res.status === 401) {
    throw new CorkAuthError(`Cork rejected the API key (HTTP 401): ${path}`);
  }
  if (res.status === 429) {
    throw new CorkRateLimitError(`Cork rate-limited the request (HTTP 429): ${path}`);
  }
  if (!res.ok) {
    throw new CorkApiError(`Cork ${path} failed: HTTP ${res.status}`, res.status);
  }
  return (await res.json()) as T;
}

// ---------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------

/** GET /clients - list clients with warranty status, integration tenants, and recent Cork Cyber Score history. */
export async function getClients(
  creds: CorkCredentials,
  params: ListClientsParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/clients', { ...params });
}

/** GET /clients/{client-uuid}/devices - devices observed for a client across all connected integrations. */
export async function getClientDevices(
  creds: CorkCredentials,
  { clientUuid, ...params }: ClientScopedPageParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/clients/${encodeURIComponent(clientUuid)}/devices`, { ...params });
}

/** GET /clients/{client-uuid}/domains - email domains observed for a client. */
export async function getClientDomains(
  creds: CorkCredentials,
  { clientUuid, ...params }: ClientScopedPageParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/clients/${encodeURIComponent(clientUuid)}/domains`, { ...params });
}

/** GET /clients/{client-uuid}/inboxes - email inboxes (users and shared mailboxes) observed for a client. */
export async function getClientInboxes(
  creds: CorkCredentials,
  { clientUuid, ...params }: ClientScopedPageParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/clients/${encodeURIComponent(clientUuid)}/inboxes`, { ...params });
}

/** GET /clients/{client-uuid}/score-history - a client's full Cork Cyber Score history, newest first. */
export async function getClientScoreHistory(
  creds: CorkCredentials,
  { clientUuid, ...params }: GetClientScoreHistoryParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/clients/${encodeURIComponent(clientUuid)}/score-history`, { ...params });
}

// ---------------------------------------------------------------------
// Risk & Compliance
// ---------------------------------------------------------------------

/** GET /compliance/client/{client-uuid}/events - policy violations and risk events detected for a client's assets. */
export async function getComplianceEvents(
  creds: CorkCredentials,
  { clientUuid, ...params }: GetComplianceEventsParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/compliance/client/${encodeURIComponent(clientUuid)}/events`, { ...params });
}

/** GET /compliance/client/{client-uuid}/notification-settings - notification/alerting rules configured for compliance events. */
export async function getComplianceNotificationSettings(
  creds: CorkCredentials,
  { clientUuid, ...params }: GetComplianceNotificationSettingsParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/compliance/client/${encodeURIComponent(clientUuid)}/notification-settings`, {
    ...params,
  });
}

/** GET /compliance/event-types - all compliance event types with descriptions and cure periods. */
export async function getComplianceEventTypes(creds: CorkCredentials): Promise<CorkPagedResponse> {
  return doGet(creds, '/compliance/event-types');
}

/** GET /vulnerabilities/software - individual software vulnerabilities with full CVE details. */
export async function getSoftwareVulnerabilities(
  creds: CorkCredentials,
  params: GetSoftwareVulnerabilitiesParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/vulnerabilities/software', { ...params });
}

/** GET /vulnerabilities/software/summary - CVEs rolled up by software product. */
export async function getSoftwareVulnerabilitySummary(
  creds: CorkCredentials,
  params: GetSoftwareVulnerabilitySummaryParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/vulnerabilities/software/summary', { ...params });
}

// ---------------------------------------------------------------------
// Integrations - read-only surface only. No connect/update/delete/resync/
// credentials/raw-data tool exists in this connector by design; see README.
// ---------------------------------------------------------------------

/** GET /integrations/available - integration types that can be connected to Cork, with required credential fields. */
export async function getAvailableIntegrations(
  creds: CorkCredentials,
  params: GetAvailableIntegrationsParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/integrations/available', { ...params });
}

/** GET /integrations/connected - integrations connected to Cork, with vendor, connection status, and sync details. */
export async function getConnectedIntegrations(
  creds: CorkCredentials,
  params: GetConnectedIntegrationsParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/integrations/connected', { ...params });
}

/** GET /integrations/{integration-uuid}/devices - devices observed from an integration. */
export async function getIntegrationDevices(
  creds: CorkCredentials,
  { integrationUuid, ...params }: IntegrationScopedPageParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/integrations/${encodeURIComponent(integrationUuid)}/devices`, { ...params });
}

/** GET /integrations/{integration-uuid}/tenants - customer tenants observed from an integration. */
export async function getIntegrationTenants(
  creds: CorkCredentials,
  { integrationUuid, ...params }: IntegrationScopedPageParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/integrations/${encodeURIComponent(integrationUuid)}/tenants`, { ...params });
}

/** GET /integrations/{integration-uuid}/users - users observed from an integration. */
export async function getIntegrationUsers(
  creds: CorkCredentials,
  { integrationUuid, ...params }: IntegrationScopedPageParams
): Promise<CorkPagedResponse> {
  return doGet(creds, `/integrations/${encodeURIComponent(integrationUuid)}/users`, { ...params });
}

// ---------------------------------------------------------------------
// Invoices
// ---------------------------------------------------------------------

/** GET /invoices - list billing invoices. */
export async function getInvoices(
  creds: CorkCredentials,
  params: ListInvoicesParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/invoices', { ...params });
}

/** GET /invoices/{invoice-uuid}/line-items - billed, top-level line items for an invoice. */
export async function getInvoiceLineItems(
  creds: CorkCredentials,
  invoiceUuid: string,
  params: PageParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, `/invoices/${encodeURIComponent(invoiceUuid)}/line-items`, { ...params });
}

// ---------------------------------------------------------------------
// Distributor
// ---------------------------------------------------------------------

/** GET /distributor/partners - partner sub-accounts managed by this distributor. Distributor accounts only. */
export async function getPartners(
  creds: CorkCredentials,
  params: PageParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/distributor/partners', { ...params });
}

// ---------------------------------------------------------------------
// Software Installer - read-only surface only. No install tool exists in
// this connector by design (it dispatches a real install to a real
// endpoint); see README.
// ---------------------------------------------------------------------

/** GET /software/installer/history - past software install attempts, most recent first. */
export async function getInstallerHistory(
  creds: CorkCredentials,
  params: GetInstallerHistoryParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/software/installer/history', { ...params });
}

/** GET /software/installer/packages - software packages available to install across supported package managers. */
export async function getSoftwarePackages(
  creds: CorkCredentials,
  params: GetSoftwarePackagesParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/software/installer/packages', { ...params });
}

/** GET /software/installer/setup - one-time setup steps for an RMM vendor that requires manual setup before installs work. */
export async function getInstallerSetup(
  creds: CorkCredentials,
  params: GetInstallerSetupParams
): Promise<Record<string, unknown>> {
  return doGet(creds, '/software/installer/setup', { ...params });
}

// ---------------------------------------------------------------------
// Warranty
// ---------------------------------------------------------------------

/** GET /warranties - active cyber warranty packages. */
export async function getWarranties(
  creds: CorkCredentials,
  params: ListWarrantiesParams = {}
): Promise<CorkPagedResponse> {
  return doGet(creds, '/warranties', { ...params });
}

// ---------------------------------------------------------------------
// Who
// ---------------------------------------------------------------------

/** GET /me - information on the authenticated user. */
export async function whoAmI(creds: CorkCredentials): Promise<Record<string, unknown>> {
  return doGet(creds, '/me');
}
