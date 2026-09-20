import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { CLIENT_TOOLS, handleClientTool, isClientTool } from './clients.js';
import { COMPLIANCE_TOOLS, handleComplianceTool, isComplianceTool } from './compliance.js';
import { VULNERABILITY_TOOLS, handleVulnerabilityTool, isVulnerabilityTool } from './vulnerabilities.js';
import { INTEGRATION_TOOLS, handleIntegrationTool, isIntegrationTool } from './integrations.js';
import { WARRANTY_TOOLS, handleWarrantyTool, isWarrantyTool } from './warranty.js';
import { INVOICE_TOOLS, handleInvoiceTool, isInvoiceTool } from './invoices.js';
import { DISTRIBUTOR_TOOLS, handleDistributorTool, isDistributorTool } from './distributor.js';
import { INSTALLER_TOOLS, handleInstallerTool, isInstallerTool } from './installer.js';
import { WHO_TOOLS, handleWhoTool, isWhoTool } from './who.js';
import type { CallToolResult } from './types.js';

export const ALL_TOOLS: Tool[] = [
  ...CLIENT_TOOLS,
  ...COMPLIANCE_TOOLS,
  ...VULNERABILITY_TOOLS,
  ...INTEGRATION_TOOLS,
  ...WARRANTY_TOOLS,
  ...INVOICE_TOOLS,
  ...DISTRIBUTOR_TOOLS,
  ...INSTALLER_TOOLS,
  ...WHO_TOOLS,
];

export async function dispatchToolCall(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  if (isClientTool(name)) return handleClientTool(name, args);
  if (isComplianceTool(name)) return handleComplianceTool(name, args);
  if (isVulnerabilityTool(name)) return handleVulnerabilityTool(name, args);
  if (isIntegrationTool(name)) return handleIntegrationTool(name, args);
  if (isWarrantyTool(name)) return handleWarrantyTool(name, args);
  if (isInvoiceTool(name)) return handleInvoiceTool(name, args);
  if (isDistributorTool(name)) return handleDistributorTool(name, args);
  if (isInstallerTool(name)) return handleInstallerTool(name, args);
  if (isWhoTool(name)) return handleWhoTool(name, args);
  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}
