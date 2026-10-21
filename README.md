# Cork MCP Server

MCP server for [Cork](https://corkinc.com/)'s cyber-insurance API for MSPs - clients and their warranty/coverage status, Cork Cyber Score history, risk & compliance events, software vulnerabilities (CVE/CVSS/EPSS/KEV), connected integrations, invoices, distributor partners, and software-installer metadata - for AI assistants and the WYRE Conduit gateway.

## Authentication

Cork authenticates with a static **Bearer API key**, generated in Cork's Admin UI (Settings -> API). Cork's OpenAPI spec also documents an OAuth2 flow for their own remote MCP server, but the underlying credential is the same API key - this connector never performs an OAuth dance, it only ever holds a live bearer key, sent as `Authorization: Bearer <key>` to Cork's API. In gateway mode the key arrives per-request via the `X-Cork-Api-Key` header; in local/stdio mode it's read once from `CORK_API_KEY`.

## Configuration

Copy [`.env.example`](.env.example) and set the variables below. Leave `CONDUIT_S2S_SECRET` empty in the example file.

| Env var | Description |
|---|---|
| `CORK_API_KEY` | Bearer API key issued by Cork's Admin UI. Required for stdio and for `AUTH_MODE=env`. Gateway mode does not read it. |
| `MCP_TRANSPORT` | `stdio` (default) or `http`. |
| `AUTH_MODE` | `env` (default, reads `CORK_API_KEY`) or `gateway` (credential arrives per-request via the `X-Cork-Api-Key` header, injected by the Conduit gateway, with no env fallback). The Docker image and Compose file set `gateway`. |
| `CONDUIT_S2S_SECRET` | Required for HTTP. Service-to-service secret checked against `X-Gateway-S2S` on every `/mcp` request. The process logs an error and exits non-zero when this is empty or a known placeholder (`changeme`, `placeholder`, `replace-with-a-real-secret`, and the other public example values). Generate one with `openssl rand -hex 32`. The value is never logged. Compose will not start when it is unset. |
| `MCP_ALLOW_INSECURE_DEV` | Set to exactly `1` only for local development to start HTTP without `CONDUIT_S2S_SECRET`. The process logs a warning, does not enforce `X-Gateway-S2S`, and binds `127.0.0.1` only. A non-loopback `MCP_HTTP_HOST` (including `0.0.0.0`) refuses to start. A known placeholder secret still refuses to start when this flag is set. |
| `MCP_HTTP_HOST` | Bind address when `MCP_TRANSPORT=http`. Unset binds `127.0.0.1`. A configured `CONDUIT_S2S_SECRET` honors this value, including `0.0.0.0`. The container image sets `0.0.0.0`. |
| `MCP_HTTP_PORT` | HTTP port. Defaults to `8080`. |
| `LOG_LEVEL` | `debug` \| `info` (default) \| `warn` \| `error`. |

`/health` stays unauthenticated and does not read credentials. The stdio transport does not use `CONDUIT_S2S_SECRET`.

### HTTP authentication

With `MCP_TRANSPORT=http` and a real `CONDUIT_S2S_SECRET`, every `/mcp` request must include `X-Gateway-S2S`. The check is `verifyS2sHeader` in [`src/s2s-verify.ts`](src/s2s-verify.ts): the header value is `t=<unix seconds>,v1=<hex>`, where the hex is HMAC-SHA256 of the literal string `t=<unix seconds>` keyed with `CONDUIT_S2S_SECRET` (64 lowercase hex characters). The timestamp must be within 300 seconds of the server clock. A missing or invalid header is HTTP 401, before the Cork API key is read.

```bash
TS=$(date +%s)
SIG=$(printf 't=%s' "$TS" | openssl dgst -sha256 -hmac "$CONDUIT_S2S_SECRET" -hex | awk '{print $NF}')
curl -sS http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H "X-Gateway-S2S: t=${TS},v1=${SIG}" \
  -H "X-Cork-Api-Key: $CORK_API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

In `AUTH_MODE=gateway`, `/mcp` also requires `X-Cork-Api-Key`. A request without that header is HTTP 401 and does not fall back to `CORK_API_KEY` in the process environment. `AUTH_MODE=env` still requires a valid `X-Gateway-S2S` header, then uses `CORK_API_KEY`.

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

## Credential scope

**This connector's own code is read-only by construction — the underlying API key is not.** Cork's own documentation states API key permissions are linked to the user who creates them; no read-only or restricted-scope key type is documented. Two separate claims, kept at different confidence levels:

- **Structurally verified (checked directly, stated with full confidence):** this connector's own code makes zero write/delete/resync/provisioning calls, and never calls the credentials or raw-data endpoints. Every function in `client.ts` calls one of the 23 documented read operations above — no wildcard/passthrough call anywhere in `src/`.
- **Vendor-documented, not independently verified (hedged deliberately):** Cork's own docs do not describe any narrower or read-only API key type. A key generated by a full-access Cork user can very likely reach the write/delete/credentials/raw-data operations this connector excludes — this has not been tested against a live key, and WYRE found no vendor-offered way to restrict it further at the credential level.

**Do not read this connector, or this README, as having established the underlying API key is itself restricted** — only that this connector's own code never attempts anything beyond its 23 read operations.

## Development

```bash
npm install
npm run build
npm test
npm run lint   # tsc --noEmit
```

## Docker

The image listens on `0.0.0.0` inside the container (`MCP_HTTP_HOST`) and defaults to `AUTH_MODE=gateway`. Publish the port on loopback and pass the S2S secret. In gateway mode the Cork API key arrives on each request as `X-Cork-Api-Key`; it is not read from the environment.

```bash
docker build -t cork-mcp .
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -p 127.0.0.1:8080:8080 \
  cork-mcp
```

Compose refuses to start when `CONDUIT_S2S_SECRET` is unset, sets `AUTH_MODE=gateway`, publishes `127.0.0.1:8080:8080`, and does not set `CORK_API_KEY` or `env_file`:

```bash
CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" docker compose up
```

Single-tenant HTTP (`AUTH_MODE=env`) still requires the S2S secret, then uses `CORK_API_KEY`:

```bash
docker run \
  -e CONDUIT_S2S_SECRET="$CONDUIT_S2S_SECRET" \
  -e AUTH_MODE=env \
  -e CORK_API_KEY="$CORK_API_KEY" \
  -p 127.0.0.1:8080:8080 \
  cork-mcp
```

Local HTTP without a secret is development-only. It binds `127.0.0.1` and logs a warning. A non-loopback `MCP_HTTP_HOST` makes startup exit:

```bash
MCP_TRANSPORT=http MCP_ALLOW_INSECURE_DEV=1 npm run start:http
```
