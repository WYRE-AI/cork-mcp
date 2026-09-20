import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  getClientDevices,
  getClientDomains,
  getClientInboxes,
  getClients,
  getClientScoreHistory,
  getCredentials,
} from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const CLIENT_TOOLS: Tool[] = [
  {
    name: 'cork_get_clients',
    description:
      "List clients with their financial protection status (warranty_status), associated integration tenants, and the 10 most recent Cork Cyber Scores (newest first). For older scores or a bounded date range, use cork_get_client_score_history. Client UUIDs from this response are required by cork_get_client_devices, cork_get_client_inboxes, cork_get_client_domains, cork_get_compliance_events, and the vulnerability tools. If the API user is a distributor, pass partner_uuid to scope results to a specific partner.",
    inputSchema: {
      type: 'object',
      properties: {
        show_hidden: { type: 'boolean', description: 'Include hidden/archived clients when true. Defaults to false.' },
        partner_uuid: {
          type: 'string',
          description: 'Filter by partner UUID (distributor users only). Obtain from cork_get_partners.',
        },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'cork_get_client_devices',
    description:
      "List devices observed for a client across all connected integrations - hostnames, IP addresses, the integration each device was seen in, whether the device can receive a future install dispatch (can_install_software), normalized OS details, resolved device type, and hardware model. Device UUIDs can be used to filter cork_get_software_vulnerabilities. Requires a client UUID from cork_get_clients.",
    inputSchema: {
      type: 'object',
      properties: {
        client_uuid: { type: 'string', description: 'Client UUID, from cork_get_clients.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['client_uuid'],
    },
  },
  {
    name: 'cork_get_client_domains',
    description:
      'List email domains observed for a client. Domain UUIDs can be used to filter cork_get_compliance_events. Requires a client UUID from cork_get_clients.',
    inputSchema: {
      type: 'object',
      properties: {
        client_uuid: { type: 'string', description: 'Client UUID, from cork_get_clients.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['client_uuid'],
    },
  },
  {
    name: 'cork_get_client_inboxes',
    description:
      'List email inboxes (users and shared mailboxes) observed for a client, with inbox type, associated domains, and the integration each inbox was sourced from. Requires a client UUID from cork_get_clients.',
    inputSchema: {
      type: 'object',
      properties: {
        client_uuid: { type: 'string', description: 'Client UUID, from cork_get_clients.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['client_uuid'],
    },
  },
  {
    name: 'cork_get_client_score_history',
    description:
      "List a client's full Cork Cyber Score history, newest first, with the risk points each category (coverage, compliance, vulnerabilities, claims) deducted from that score. Use created_after/created_before to bound a period (both inclusive) for trend reporting - cork_get_clients only carries the 10 most recent scores. Requires a client UUID from cork_get_clients.",
    inputSchema: {
      type: 'object',
      properties: {
        client_uuid: { type: 'string', description: 'Client UUID, from cork_get_clients.' },
        created_after: { type: 'string', format: 'date-time', description: 'Inclusive lower bound.' },
        created_before: { type: 'string', format: 'date-time', description: 'Inclusive upper bound.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['client_uuid'],
    },
  },
];

const TOOL_NAMES = new Set(CLIENT_TOOLS.map((t) => t.name));
export function isClientTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleClientTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_get_clients') {
      return textResult(
        await getClients(creds!, {
          show_hidden: args.show_hidden as boolean | undefined,
          partner_uuid: args.partner_uuid as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_client_devices') {
      return textResult(
        await getClientDevices(creds!, {
          clientUuid: args.client_uuid as string,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_client_domains') {
      return textResult(
        await getClientDomains(creds!, {
          clientUuid: args.client_uuid as string,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_client_inboxes') {
      return textResult(
        await getClientInboxes(creds!, {
          clientUuid: args.client_uuid as string,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_client_score_history') {
      return textResult(
        await getClientScoreHistory(creds!, {
          clientUuid: args.client_uuid as string,
          created_after: args.created_after as string | undefined,
          created_before: args.created_before as string | undefined,
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
