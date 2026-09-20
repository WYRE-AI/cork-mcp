/**
 * Cork authenticates with a static Bearer API key, generated in Cork's
 * Admin UI (Settings -> API). Cork's OpenAPI spec also documents an OAuth2
 * flow for their own remote MCP server, but the underlying credential is
 * the same API key - this connector, like every other WYRE Conduit sidecar
 * for a static-key vendor, receives the key per-request via a custom header
 * (never OAuth) and itself builds `Authorization: Bearer <key>` when calling
 * Cork's API. See README's Authentication section.
 */
export interface CorkCredentials {
  apiKey: string;
}

/** Thrown when Cork rejects the API key (HTTP 401) - distinct from rate limiting so callers get an honest error. */
export class CorkAuthError extends Error {}

/** Thrown when Cork rate-limits the request (HTTP 429) - distinct from an auth failure. */
export class CorkRateLimitError extends Error {}

/** Thrown for any other non-2xx / unexpected vendor response. */
export class CorkApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
  }
}

export type SoftwarePackageManagerKey = 'WINGET' | 'CHOC';
export type VulnerabilityPriority = 'critical' | 'accelerated' | 'routine';
export type SortDirection = 'asc' | 'desc';

export interface PageParams {
  page?: number;
  page_size?: number;
}

// ---------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------

export interface ListClientsParams extends PageParams {
  show_hidden?: boolean;
  partner_uuid?: string;
}

export interface ClientScopedPageParams extends PageParams {
  clientUuid: string;
}

export interface GetClientScoreHistoryParams extends ClientScopedPageParams {
  created_after?: string;
  created_before?: string;
}

// ---------------------------------------------------------------------
// Risk & Compliance
// ---------------------------------------------------------------------

export interface GetComplianceEventsParams extends ClientScopedPageParams {
  event_type?: string;
  device_uuid?: string;
  inbox_uuid?: string;
  domain_uuid?: string;
  at_risk?: boolean;
  show_silenced?: boolean;
  show_resolved?: boolean;
  created_after?: string;
  created_before?: string;
  resolved_after?: string;
  resolved_before?: string;
}

export interface GetComplianceNotificationSettingsParams extends ClientScopedPageParams {
  device_uuid?: string;
  inbox_uuid?: string;
  domain_uuid?: string;
}

export interface GetSoftwareVulnerabilitiesParams extends PageParams {
  sw_vendor?: string;
  client_uuid?: string;
  partner_uuid?: string;
  sort_direction?: SortDirection;
  sort_by?: 'sw_vendor' | 'sw_product';
  only_known_exploited?: boolean;
  minimum_cvss_score?: number;
  minimum_epss_score?: number;
  minimum_priority?: VulnerabilityPriority;
  device_uuid?: string;
}

export interface GetSoftwareVulnerabilitySummaryParams extends PageParams {
  sw_vendor?: string;
  client_uuid?: string;
  partner_uuid?: string;
  sort_direction?: SortDirection;
  sort_by?: 'sw_vendor' | 'sw_product' | 'num_impacted_devices' | 'num_impacted_versions';
}

// ---------------------------------------------------------------------
// Integrations
// ---------------------------------------------------------------------

export interface GetAvailableIntegrationsParams extends PageParams {
  vendor_type?: string;
}

export interface GetConnectedIntegrationsParams extends PageParams {
  partner_uuid?: string;
}

export interface IntegrationScopedPageParams extends PageParams {
  integrationUuid: string;
  tenant_uuid?: string;
}

// ---------------------------------------------------------------------
// Invoices
// ---------------------------------------------------------------------

export interface ListInvoicesParams extends PageParams {
  partner_uuid?: string;
}

// ---------------------------------------------------------------------
// Software Installer
// ---------------------------------------------------------------------

export interface GetInstallerHistoryParams extends PageParams {
  client_uuid?: string;
  device_uuid?: string;
  partner_uuid?: string;
}

export interface GetSoftwarePackagesParams extends PageParams {
  package_manager_key?: SoftwarePackageManagerKey;
  search?: string;
}

export interface GetInstallerSetupParams {
  vendor_key: string;
  package_manager_key: SoftwarePackageManagerKey;
}

// ---------------------------------------------------------------------
// Warranty / Distributor
// ---------------------------------------------------------------------

export interface ListWarrantiesParams extends PageParams {
  partner_uuid?: string;
}

/**
 * Generic paginated-list envelope shared by nearly every Cork list
 * endpoint. Response bodies are passed through as received - this
 * connector doesn't re-model Cork's full field set, only what a caller
 * needs to page and chain calls (see each tool's own JSDoc for the fields
 * that matter for chaining, e.g. client/device/integration UUIDs).
 */
export interface CorkPagedResponse<T = unknown> {
  data: T[];
  page?: number;
  page_size?: number;
  total?: number;
  [key: string]: unknown;
}
