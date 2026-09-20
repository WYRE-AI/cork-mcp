import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, whoAmI } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, requireCredentials, textResult } from './shared.js';

export const WHO_TOOLS: Tool[] = [
  {
    name: 'cork_who_am_i',
    description: 'Get information on the authenticated Cork user (identity, role, and partner/distributor scope). Useful for a quick credential sanity check.',
    inputSchema: { type: 'object', properties: {} },
  },
];

const TOOL_NAMES = new Set(WHO_TOOLS.map((t) => t.name));
export function isWhoTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleWhoTool(name: string, _args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_who_am_i') {
      return textResult(await whoAmI(creds!));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
