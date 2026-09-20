import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getWarranties } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const WARRANTY_TOOLS: Tool[] = [
  {
    name: 'cork_get_warranties',
    description:
      "List active cyber warranty packages. To identify which clients lack coverage, check the warranty_status field in cork_get_clients results - clients with 'unwarranted' status have no active warranty.",
    inputSchema: {
      type: 'object',
      properties: {
        partner_uuid: { type: 'string', description: 'Filter by partner UUID (distributor users only).' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
];

const TOOL_NAMES = new Set(WARRANTY_TOOLS.map((t) => t.name));
export function isWarrantyTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleWarrantyTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_get_warranties') {
      return textResult(
        await getWarranties(creds!, {
          partner_uuid: args.partner_uuid as string | undefined,
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
