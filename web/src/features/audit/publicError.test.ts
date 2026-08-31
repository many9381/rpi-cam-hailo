import { renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { ApiError, UnauthorizedError } from '../../api/client';
import { LanguageProvider, useTranslation } from '../../i18n';
import { auditErrorMessage } from './publicError';

function realT() {
  const { result } = renderHook(() => useTranslation(), { wrapper: LanguageProvider });
  return result.current.t;
}

describe('auditErrorMessage', () => {
  const t = realT();

  it.each([
    ['E_AUDIT_QUERY_INVALID', 'Audit query is invalid.'],
    ['E_AUDIT_UNAVAILABLE', 'Audit records are temporarily unavailable.'],
  ])('maps allowlisted code %s without using backend text', (code, expected) => {
    expect(auditErrorMessage(
      new ApiError(503, code, 'private SQL /var/lib/camera-firmware/security.db'), t,
    )).toBe(expected);
  });

  it.each([
    new ApiError(403, 'E_AUTHORIZATION_REQUIRED', 'private role detail'),
    new ApiError(503, 'E_PRIVATE_SQLITE_PATH', '/var/lib/private.db'),
    new UnauthorizedError('private-session-detail'),
    new Error('private SQL and cursor internals'),
    'private backend string',
  ])('maps unknown errors to one fixed generic message', (error) => {
    expect(auditErrorMessage(error, t)).toBe('Audit request failed.');
  });

  it.each([
    'constructor',
    '__proto__',
    'toString',
    'valueOf',
  ])('rejects inherited object key %s as an unknown code', (code) => {
    const message = auditErrorMessage(new ApiError(503, code, 'private detail'), t);

    expect(message).toBe('Audit request failed.');
    expect(typeof message).toBe('string');
  });

  it.each([
    undefined,
    null,
    503,
    { toString: () => 'E_AUDIT_UNAVAILABLE' },
  ])('rejects malformed ApiError code %o without coercion', (code) => {
    const malformed = new ApiError(503, code as unknown as string, 'private detail');

    expect(auditErrorMessage(malformed, t)).toBe('Audit request failed.');
  });
});
