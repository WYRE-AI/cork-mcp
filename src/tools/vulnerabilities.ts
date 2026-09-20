import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getSoftwareVulnerabilities, getSoftwareVulnerabilitySummary } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const VULNERABILITY_TOOLS: Tool[] = [
  {
    name: 'cork_get_software_vulnerabilities',
    description:
      'List individual software vulnerabilities with full CVE details including CVSS score, EPSS score, KEV (known exploited) status, and impacted version. Filter by minimum_cvss_score, minimum_epss_score, minimum_priority, or only_known_exploited=true to focus on the highest-risk findings. Scope by client_uuid or device_uuid.',
    inputSchema: {
      type: 'object',
      properties: {
        sw_vendor: { type: 'string', description: 'Filter by software vendor.' },
        client_uuid: { type: 'string', description: 'Filter by client, from cork_get_clients.' },
        partner_uuid: { type: 'string', description: 'Filter by partner, for distributors only.' },
        device_uuid: { type: 'string', description: 'Filter by device, from cork_get_client_devices.' },
        sort_direction: { type: 'string', enum: ['asc', 'desc'] },
        sort_by: { type: 'string', enum: ['sw_vendor', 'sw_product'] },
        only_known_exploited: { type: 'boolean', description: 'Only show known exploited vulnerabilities.' },
        minimum_cvss_score: { type: 'number', minimum: 0, maximum: 10, description: 'Minimum CVSS score. Defaults to 0.' },
        minimum_epss_score: { type: 'number', minimum: 0, maximum: 1, description: 'Minimum EPSS score. Defaults to 0.' },
        minimum_priority: { type: 'string', enum: ['critical', 'accelerated', 'routine'] },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'cork_get_software_vulnerability_summary',
    description:
      'Get a rollup of CVEs grouped by software product, showing number of impacted devices, impacted versions, and highest severity rating. Use client_uuid to scope to a single client. Follow up with cork_get_software_vulnerabilities to drill into specific CVEs for a product.',
    inputSchema: {
      type: 'object',
      properties: {
        sw_vendor: { type: 'string', description: 'Filter by software vendor.' },
        client_uuid: { type: 'string', description: 'Filter by client, from cork_get_clients.' },
        partner_uuid: { type: 'string', description: 'Filter by partner, for distributors only.' },
        sort_direction: { type: 'string', enum: ['asc', 'desc'] },
        sort_by: { type: 'string', enum: ['sw_vendor', 'sw_product', 'num_impacted_devices', 'num_impacted_versions'] },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
];

const TOOL_NAMES = new Set(VULNERABILITY_TOOLS.map((t) => t.name));
export function isVulnerabilityTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleVulnerabilityTool(
  name: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_get_software_vulnerabilities') {
      return textResult(
        await getSoftwareVulnerabilities(creds!, {
          sw_vendor: args.sw_vendor as string | undefined,
          client_uuid: args.client_uuid as string | undefined,
          partner_uuid: args.partner_uuid as string | undefined,
          device_uuid: args.device_uuid as string | undefined,
          sort_direction: args.sort_direction as 'asc' | 'desc' | undefined,
          sort_by: args.sort_by as 'sw_vendor' | 'sw_product' | undefined,
          only_known_exploited: args.only_known_exploited as boolean | undefined,
          minimum_cvss_score: args.minimum_cvss_score as number | undefined,
          minimum_epss_score: args.minimum_epss_score as number | undefined,
          minimum_priority: args.minimum_priority as 'critical' | 'accelerated' | 'routine' | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_software_vulnerability_summary') {
      return textResult(
        await getSoftwareVulnerabilitySummary(creds!, {
          sw_vendor: args.sw_vendor as string | undefined,
          client_uuid: args.client_uuid as string | undefined,
          partner_uuid: args.partner_uuid as string | undefined,
          sort_direction: args.sort_direction as 'asc' | 'desc' | undefined,
          sort_by: args.sort_by as 'sw_vendor' | 'sw_product' | 'num_impacted_devices' | 'num_impacted_versions' | undefined,
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
