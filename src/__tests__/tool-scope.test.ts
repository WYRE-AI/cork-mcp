import { describe, expect, it } from 'vitest';
import { ALL_TOOLS } from '../tools/index.js';

/**
 * Hard scope boundary (see README's Scope section and the PR description for
 * the full accounting against Cork's OpenAPI spec): this connector must
 * NEVER expose a tool that returns raw stored third-party credentials, or
 * that mutates/provisions/deletes/resyncs anything. Pin the exact tool set
 * so an accidental addition - a copy-pasted "get_integration_credentials",
 * "install_software", "delete_integration", "resync_integration", or any
 * other write/credential-exposing tool - fails this test immediately rather
 * than silently shipping.
 */
describe('ALL_TOOLS scope boundary', () => {
  const EXPECTED_TOOL_NAMES = [
    // Clients
    'cork_get_clients',
    'cork_get_client_devices',
    'cork_get_client_domains',
    'cork_get_client_inboxes',
    'cork_get_client_score_history',
    // Risk & Compliance
    'cork_get_compliance_events',
    'cork_get_compliance_notification_settings',
    'cork_get_compliance_event_types',
    'cork_get_software_vulnerabilities',
    'cork_get_software_vulnerability_summary',
    // Integrations (read-only subset)
    'cork_get_available_integrations',
    'cork_get_connected_integrations',
    'cork_get_integration_devices',
    'cork_get_integration_tenants',
    'cork_get_integration_users',
    // Warranty
    'cork_get_warranties',
    // Invoice
    'cork_get_invoices',
    'cork_get_invoice_line_items',
    // Distributor (read-only subset)
    'cork_get_partners',
    // Software Installer (read-only subset)
    'cork_get_installer_history',
    'cork_get_software_packages',
    'cork_get_installer_setup',
    // Who
    'cork_who_am_i',
  ].sort();

  it('exposes exactly this connector\'s 23 read-only tools - nothing more, nothing less', () => {
    const names = ALL_TOOLS.map((t) => t.name).sort();
    expect(names).toEqual(EXPECTED_TOOL_NAMES);
    expect(names).toHaveLength(23);
  });

  it('never exposes a credential-exposing, write, delete, resync, or provisioning tool', () => {
    // Forbidden as a whole underscore-token, not a substring - so this does
    // NOT false-positive on 'cork_get_installer_history'/'cork_get_installer_setup'
    // ('installer' !== 'install') or on 'cork_get_invoices' ('invoices' has no
    // banned token either.
    const FORBIDDEN_TOKENS = new Set([
      'credential',
      'credentials',
      'install', // the write install-software dispatch, distinct from 'installer'
      'delete',
      'resync',
      'provision',
      'raw', // the raw-data presigned-download-URL endpoint
      'connect', // connect-integration (create)
      'update', // update-integration
    ]);

    for (const tool of ALL_TOOLS) {
      const tokens = tool.name.split('_');
      for (const token of tokens) {
        expect(
          FORBIDDEN_TOKENS.has(token),
          `Tool "${tool.name}" contains forbidden token "${token}" - this connector must stay read-only and non-credential-exposing.`
        ).toBe(false);
      }
    }
  });

  it('every tool name is prefixed with cork_', () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.name.startsWith('cork_')).toBe(true);
    }
  });
});
