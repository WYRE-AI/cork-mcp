# Cork MCP Server

MCP server for [Cork](https://corkinc.com/)'s cyber-insurance API for MSPs - clients and their warranty/coverage status, Cork Cyber Score history, risk & compliance events, software vulnerabilities (CVE/CVSS/EPSS/KEV), connected integrations, invoices, distributor partners, and software-installer metadata - for AI assistants and the WYRE Conduit gateway.

## Authentication

Cork authenticates with a static **Bearer API key**, generated in Cork's Admin UI (Settings -> API). Cork's OpenAPI spec also documents an OAuth2 flow for their own remote MCP server, but the underlying credential is the same API key - this connector never performs an OAuth dance, it only ever holds a live bearer key, sent as `Authorization: Bearer <key>` to Cork's API. In gateway mode the key arrives per-request via the `X-Cork-Api-Key` header; in local/stdio mode it's read once from `CORK_API_KEY`.

## Configuration

| Env var | Description |
|---|---|
| `CORK_API_KEY` | Bearer API key issued by Cork's Admin UI. |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default, reads the var above) or `gateway` (credential arrives per-request via the `X-Cork-Api-Key` header, injected by the Conduit gateway). |
| `CONDUIT_S2S_SECRET` | When set, the HTTP transport requires a valid `X-Gateway-S2S` header (Conduit sidecar auth) on every `/mcp` request. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

## Tools

### Clients
- `cork_get_clients` - list clients with warranty status, integration tenants, and recent Cork Cyber Scores.
- `cork_get_client_devices` - list devices observed for a client across all connected integrations.
- `cork_get_client_domains` - list email domains observed for a client.
- `cork_get_client_inboxes` - list email inboxes observed for a client.
- `cork_get_client_score_history` - list a client's full Cork Cyber Score history, newest first.

### Risk & Compliance
- `cork_get_compliance_events` - list policy violations and risk events detected for a client's assets.
- `cork_get_compliance_notification_settings` - list notification/alerting rules for compliance events.
- `cork_get_compliance_event_types` - list all compliance event types with descriptions and cure periods.
- `cork_get_software_vulnerabilities` - list individual CVEs with CVSS/EPSS/KEV details.
- `cork_get_software_vulnerability_summary` - get a rollup of CVEs grouped by software product.

### Integrations - read-only subset
- `cork_get_available_integrations` - list integration types that can be connected to Cork.
- `cork_get_connected_integrations` - list integrations connected to Cork.
- `cork_get_integration_devices` - list devices observed from an integration.
- `cork_get_integration_tenants` - list customer tenants observed from an integration.
- `cork_get_integration_users` - list users observed from an integration.

### Warranty
- `cork_get_warranties` - list active cyber warranty packages.

### Invoice
- `cork_get_invoices` - list billing invoices.
- `cork_get_invoice_line_items` - list billed line items for an invoice.

### Distributor - read-only subset
- `cork_get_partners` - list partner sub-accounts managed by this distributor.

### Software Installer - read-only subset
- `cork_get_installer_history` - list past software install attempts.
- `cork_get_software_packages` - list software packages available to install.
- `cork_get_installer_setup` - get one-time RMM setup instructions for software installs.

### Who
- `cork_who_am_i` - get information on the authenticated user.

## Scope

**This is a deliberately narrow, read-only, non-credential-exposing v1 surface, hard-scoped to exactly 23 of Cork's 31 operations (29 documented paths).** Every tool is classified `isAdmin: true` in the Conduit gateway given the sensitivity of insurance/risk/compliance data. Roughly a third of Cork's full API is write- or secret-exposing; none of it is implemented here, by design, not by oversight:

**Hard-excluded (credential-exposing) - never implemented:**
- `GET /integrations/{uuid}/credentials` (`get-integration-credentials`) - returns the integration's raw stored third-party secrets (`credentials: {...}`).

**Hard-excluded (bulk raw-data exfiltration, excluded out of caution alongside credentials):**
- `GET /integrations/{uuid}/raw-data` (`get-integration-raw-data`) - returns a presigned download URL (10-minute expiry) to a client's full raw synced integration data. Not a credential return, but a bulk-data-exfiltration vector gated by "requires distributor privileges" in Cork's own spec. Flagged explicitly for review in the wiring PR rather than silently included.

**Hard-excluded (provisioning/mutation) - never implemented:**
- `POST /distributor/partners` (`provision-partner`) - provisions a new Partner account.
- `POST /integrations` (`connect-integration`) - connects a new integration and immediately begins syncing data.
- `PATCH /integrations/{uuid}` (`update-integration`) - updates an integration's name and/or credentials.
- `DELETE /integrations/{uuid}` (`delete-integration`) - deletes an integration.
- `POST /integrations/{uuid}/resync` (`resync-integration`) - manually triggers a data refresh.
- `POST /software/installer/install` (`install-software`) - dispatches a real software install to a real managed endpoint through the client's RMM. A genuine remote-software-provisioning action.

They can be added as a follow-up if there's demand, after a deliberate scope decision - not by default.

## Development

```bash
npm install
npm run build
npm test
npm run lint   # tsc --noEmit
```

## Docker

```bash
docker build -t cork-mcp .
docker run -p 8080:8080 -e CORK_API_KEY=... cork-mcp
```
