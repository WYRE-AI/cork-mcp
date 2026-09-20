import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getInvoiceLineItems, getInvoices } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const INVOICE_TOOLS: Tool[] = [
  {
    name: 'cork_get_invoices',
    description:
      'List billing invoices. Returns invoice UUIDs required by cork_get_invoice_line_items. If the API user is a distributor, pass partner_uuid to scope results to a specific partner.',
    inputSchema: {
      type: 'object',
      properties: {
        partner_uuid: { type: 'string' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'cork_get_invoice_line_items',
    description:
      "List billed, top-level line items for an invoice (obtained via cork_get_invoices). Only items with a nonzero total billed are returned; discount line items are included and carry a negative total_billed. Sub-items billed as part of a parent line item (e.g. individual licenses within a bundle) are nested under that item's children field, and always carry a total_billed of 0 since their amount is rolled into the parent.",
    inputSchema: {
      type: 'object',
      properties: {
        invoice_uuid: { type: 'string', description: 'Invoice UUID, from cork_get_invoices.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['invoice_uuid'],
    },
  },
];

const TOOL_NAMES = new Set(INVOICE_TOOLS.map((t) => t.name));
export function isInvoiceTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleInvoiceTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_get_invoices') {
      return textResult(
        await getInvoices(creds!, {
          partner_uuid: args.partner_uuid as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_invoice_line_items') {
      return textResult(
        await getInvoiceLineItems(creds!, args.invoice_uuid as string, {
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
