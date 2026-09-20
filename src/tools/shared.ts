import type { CorkCredentials } from '../types.js';
import type { CallToolResult } from './types.js';

export function textResult(value: unknown): CallToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text }] };
}

export function errorResult(message: string): CallToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}

/** Returns an error CallToolResult if credentials are missing, else null. */
export function requireCredentials(creds: CorkCredentials | null): CallToolResult | null {
  if (!creds) {
    return errorResult('No Cork credentials configured. Set CORK_API_KEY.');
  }
  return null;
}

/** Shared input-schema fragment for the offset-paginated list endpoints (every Cork list endpoint). */
export const PAGE_PARAMS_PROPERTIES = {
  page: { type: 'number', description: 'Page number (1-based). Defaults to 1.' },
  page_size: { type: 'number', description: 'Items per page (max 100). Defaults to 10.' },
} as const;
