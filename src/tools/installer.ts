/**
 * Software Installer - read-only surface only. Cork's Software Installer
 * tag has 4 operations; this file implements the 3 reads. POST
 * /software/installer/install (install-software) is a genuine remote
 * software-provisioning action - it dispatches an install to a real
 * managed endpoint through the client's RMM. Hard-excluded, never
 * implemented here.
 */
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getInstallerHistory, getInstallerSetup, getSoftwarePackages } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const INSTALLER_TOOLS: Tool[] = [
  {
    name: 'cork_get_installer_history',
    description:
      "List past software install attempts (most recent first) with dispatch state, target client/device, package, and any errors. Filter by client_uuid or device_uuid. state is one of queued, running, success, partial, error - 'success' means the RMM accepted the job, not that the on-device install finished.",
    inputSchema: {
      type: 'object',
      properties: {
        client_uuid: { type: 'string', description: 'Filter to installs targeting a single client. Obtain from cork_get_clients.' },
        device_uuid: { type: 'string', description: 'Filter to installs targeting a single mapped device. Obtain from cork_get_client_devices.' },
        partner_uuid: {
          type: 'string',
          description:
            "Filter by partner UUID (distributor users only). Distributors scoping to a child partner's client or device must set this too - client_uuid/device_uuid alone stay scoped to your own partner's installs.",
        },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'cork_get_software_packages',
    description:
      'List software packages available to install across supported package managers (WinGet, Chocolatey). Filter by package_manager_key or search (substring match against name/publisher). Returns package_id values that would be used by a future install dispatch - this connector does not implement software install itself.',
    inputSchema: {
      type: 'object',
      properties: {
        package_manager_key: { type: 'string', enum: ['WINGET', 'CHOC'], description: 'Filter by package manager key.' },
        search: { type: 'string', description: 'Case-insensitive substring match against package name and publisher.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'cork_get_installer_setup',
    description:
      "Get the one-time setup steps for an RMM vendor that requires manual setup before software installs work - the script to create in the RMM, its exact name, settings to match, and variables to declare. Use when a connected integration shows installer.requires_manual_setup=true (and the package manager is missing from installer.configured_package_managers).",
    inputSchema: {
      type: 'object',
      properties: {
        vendor_key: {
          type: 'string',
          description: "RMM vendor key to set up (e.g. NINJA_RMM, DATTO_RMM). Obtain from a connected integration's vendor.key where installer.requires_manual_setup is true.",
        },
        package_manager_key: { type: 'string', enum: ['WINGET', 'CHOC'], description: 'Package manager the setup is for.' },
      },
      required: ['vendor_key', 'package_manager_key'],
    },
  },
];

const TOOL_NAMES = new Set(INSTALLER_TOOLS.map((t) => t.name));
export function isInstallerTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleInstallerTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'cork_get_installer_history') {
      return textResult(
        await getInstallerHistory(creds!, {
          client_uuid: args.client_uuid as string | undefined,
          device_uuid: args.device_uuid as string | undefined,
          partner_uuid: args.partner_uuid as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_software_packages') {
      return textResult(
        await getSoftwarePackages(creds!, {
          package_manager_key: args.package_manager_key as 'WINGET' | 'CHOC' | undefined,
          search: args.search as string | undefined,
          page: args.page as number | undefined,
          page_size: args.page_size as number | undefined,
        })
      );
    }

    if (name === 'cork_get_installer_setup') {
      return textResult(
        await getInstallerSetup(creds!, {
          vendor_key: args.vendor_key as string,
          package_manager_key: args.package_manager_key as 'WINGET' | 'CHOC',
        })
      );
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
