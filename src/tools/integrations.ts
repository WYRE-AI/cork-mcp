/**
 * Integrations - read-only, non-credential-exposing surface only.
 *
 * HARD SCOPE BOUNDARY (see README's Scope section for the full accounting):
 * this file deliberately implements ONLY the 5 read tools below. It never
 * implements:
 *   - GET  /integrations/{uuid}/credentials - returns the integration's raw
 *     stored third-party secrets (`credentials: {...}`). Credential
 *     exposure, hard-excluded regardless of HTTP verb.
 *   - GET  /integrations/{uuid}/raw-data - returns a presigned download URL
 *     (10-minute expiry) to a client's full raw synced integration data.
 *     Not a credential-return endpoint, but a bulk-data-exfiltration vector
 *     gated by "requires distributor privileges" in Cork's own spec -
 *     excluded out of caution alongside credentials rather than implemented
 *     on the assumption it's safe. Flagged explicitly for review; see the
 *     PR description.
 *   - POST   /integrations - connects (creates) a new integration and
 *     immediately begins syncing data. A write.
 *   - PATCH  /integrations/{uuid} - updates an integration's name and/or
 *     credentials. A write (and can itself set new credentials).
 *   - DELETE /integrations/{uuid} - deletes an integration. A write.
 *   - POST   /integrations/{uuid}/resync - manually triggers a data
 *     refresh. A write/action.
 */
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  getAvailableIntegrations,
  getConnectedIntegrations,
  getCredentials,
  getIntegrationDevices,
  getIntegrationTenants,
  getIntegrationUsers,
} from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const INTEGRATION_TOOLS: Tool[] = [
  {
    name: 'cork_get_available_integrations',
    description:
      'List integration types that can be connected to Cork, including required credential fields. Metadata about what CAN be connected, not what IS connected - see cork_get_connected_integrations for that.',
    inputSchema: {
      type: 'object',
      properties: {
        vendor_type: { type: 'string', description: "Filter by vendor type (e.g. 'rmm', 'edr', 'mfa')." },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'cork_get_connected_integrations',
    description:
      "List integrations connected to Cork - vendor, connection status, and sync details. RMM integrations also carry an installer block describing whether software installs can run through them (capable, requires_manual_setup, authorized, configured_package_managers). Use with cork_get_client_devices to see which integration a device is mapped through. Discovers integration UUIDs needed by cork_get_integration_devices, cork_get_integration_users, and cork_get_integration_tenants.",
    inputSchema: {
      type: 'object',
      properties: {
        partner_uuid: {
          type: 'string',
          description: 'Filter by partner UUID (distributor users only). Obtain from cork_get_partners.',
        },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'cork_get_integration_devices',
    description:
      'List devices observed from an integration - hostnames, IP addresses, device properties, and normalized OS details for devices that have been mapped.',
    inputSchema: {
      type: 'object',
      properties: {
        integration_uuid: { type: 'string', description: 'Integration UUID, from cork_get_connected_integrations.' },
        tenant_uuid: { type: 'string' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['integration_uuid'],
    },
  },
  {
    name: 'cork_get_integration_tenants',
    description: 'List customer tenants observed from an integration.',
    inputSchema: {
      type: 'object',
      properties: {
        integration_uuid: { type: 'string', description: 'Integration UUID, from cork_get_connected_integrations.' },
        tenant_uuid: { type: 'string' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['integration_uuid'],
    },
  },
  {
    name: 'cork_get_integration_users',
    description: 'List users observed from an integration.',
    inputSchema: {
      type: 'object',
      properties: {
        integration_uuid: { type: 'string', description: 'Integration UUID, from cork_get_connected_integrations.' },
        tenant_uuid: { type: 'string' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['integration_uuid'],
    },
  },
];

const TOOL_NAMES = new Set(INTEGRATION_TOOLS.map((t) => t.name));
export function isIntegrationTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleIntegrationTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_get_available_integrations') {
      return textResult(
        await getAvailableIntegrations(creds!, {
          vendor_type: args.vendor_type as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_connected_integrations') {
      return textResult(
        await getConnectedIntegrations(creds!, {
          partner_uuid: args.partner_uuid as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_integration_devices') {
      return textResult(
        await getIntegrationDevices(creds!, {
          integrationUuid: args.integration_uuid as string,
          tenant_uuid: args.tenant_uuid as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_integration_tenants') {
      return textResult(
        await getIntegrationTenants(creds!, {
          integrationUuid: args.integration_uuid as string,
          tenant_uuid: args.tenant_uuid as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_integration_users') {
      return textResult(
        await getIntegrationUsers(creds!, {
          integrationUuid: args.integration_uuid as string,
          tenant_uuid: args.tenant_uuid as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
