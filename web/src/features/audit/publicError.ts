import { ApiError } from '../../api/client';

export function auditErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'E_AUDIT_QUERY_INVALID':
        return 'Audit query is invalid.';
      case 'E_AUDIT_UNAVAILABLE':
        return 'Audit records are temporarily unavailable.';
    }
  }
  return 'Audit request failed.';
}
