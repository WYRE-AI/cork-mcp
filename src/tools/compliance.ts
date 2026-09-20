import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  getComplianceEvents,
  getComplianceEventTypes,
  getComplianceNotificationSettings,
  getCredentials,
} from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const COMPLIANCE_TOOLS: Tool[] = [
  {
    name: 'cork_get_compliance_events',
    description:
      'List policy violations and risk events detected for a client\'s assets. Filter by event_type (use cork_get_compliance_event_types for valid values), device, inbox, or domain UUID. Use at_risk=true to show only currently active risks. Resolved events are excluded by default; set show_resolved=true to include them.',
    inputSchema: {
      type: 'object',
      properties: {
        client_uuid: { type: 'string', description: 'Client UUID, from cork_get_clients.' },
        event_type: { type: 'string', description: 'Filter by event type. Use cork_get_compliance_event_types for valid values.' },
        device_uuid: { type: 'string', description: 'Filter to a specific device UUID from cork_get_client_devices.' },
        inbox_uuid: { type: 'string', description: 'Filter to a specific inbox UUID from cork_get_client_inboxes.' },
        domain_uuid: { type: 'string', description: 'Filter to a specific domain UUID from cork_get_client_domains.' },
        at_risk: { type: 'boolean', description: 'When true, only return currently active (unresolved, unsuppressed) risk events.' },
        show_silenced: { type: 'boolean', description: 'Include silenced/suppressed events in results. Defaults to false.' },
        show_resolved: {
          type: 'boolean',
          description: 'Include resolved events in results. Required to use resolved_after/resolved_before. Defaults to false.',
        },
        created_after: { type: 'string', format: 'date-time' },
        created_before: { type: 'string', format: 'date-time' },
        resolved_after: { type: 'string', format: 'date-time', description: 'Requires show_resolved=true.' },
        resolved_before: { type: 'string', format: 'date-time', description: 'Requires show_resolved=true.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['client_uuid'],
    },
  },
  {
    name: 'cork_get_compliance_notification_settings',
    description:
      'List the notification and alerting rules configured for compliance events on a client\'s assets - which event types trigger alerts and how they are routed.',
    inputSchema: {
      type: 'object',
      properties: {
        client_uuid: { type: 'string', description: 'Client UUID, from cork_get_clients.' },
        device_uuid: { type: 'string' },
        inbox_uuid: { type: 'string' },
        domain_uuid: { type: 'string' },
        ...PAGE_PARAMS_PROPERTIES,
      },
      required: ['client_uuid'],
    },
  },
  {
    name: 'cork_get_compliance_event_types',
    description: 'List all compliance event types with their descriptions and cure periods. Use to discover valid event_type values before filtering cork_get_compliance_events.',
    inputSchema: { type: 'object', properties: {} },
  },
];

const TOOL_NAMES = new Set(COMPLIANCE_TOOLS.map((t) => t.name));
export function isComplianceTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleComplianceTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_get_compliance_events') {
      return textResult(
        await getComplianceEvents(creds!, {
          clientUuid: args.client_uuid as string,
          event_type: args.event_type as string | undefined,
          device_uuid: args.device_uuid as string | undefined,
          inbox_uuid: args.inbox_uuid as string | undefined,
          domain_uuid: args.domain_uuid as string | undefined,
          at_risk: args.at_risk as boolean | undefined,
          show_silenced: args.show_silenced as boolean | undefined,
          show_resolved: args.show_resolved as boolean | undefined,
          created_after: args.created_after as string | undefined,
          created_before: args.created_before as string | undefined,
          resolved_after: args.resolved_after as string | undefined,
          resolved_before: args.resolved_before as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_compliance_notification_settings') {
      return textResult(
        await getComplianceNotificationSettings(creds!, {
          clientUuid: args.client_uuid as string,
          device_uuid: args.device_uuid as string | undefined,
          inbox_uuid: args.inbox_uuid as string | undefined,
          domain_uuid: args.domain_uuid as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_compliance_event_types') {
      return textResult(await getComplianceEventTypes(creds!));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
