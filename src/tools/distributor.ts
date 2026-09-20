/**
 * Distributor - read-only surface only. Cork's Distributor tag has 2
 * operations; this file implements only the GET. POST
 * /distributor/partners (provision-partner) provisions a brand-new Partner
 * account and is a hard-excluded write - never implemented here.
 */
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getPartners } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const DISTRIBUTOR_TOOLS: Tool[] = [
  {
    name: 'cork_get_partners',
    description:
      'List partner sub-accounts managed by this distributor. Returns partner UUIDs that can be passed as partner_uuid to cork_get_clients and other tools to scope results to a specific partner. Distributor accounts only.',
    inputSchema: {
      type: 'object',
      properties: { ...PAGE_PARAMS_PROPERTIES },
    },
  },
];

const TOOL_NAMES = new Set(DISTRIBUTOR_TOOLS.map((t) => t.name));
export function isDistributorTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleDistributorTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_get_partners') {
      return textResult(
        await getPartners(creds!, {
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
