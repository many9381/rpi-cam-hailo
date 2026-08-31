import { describe, expect, it } from 'vitest';

import { ApiError, UnauthorizedError } from '../../api/client';
import { userManagementErrorMessage } from './publicError';

describe('userManagementErrorMessage', () => {
  it.each([
    ['E_USERNAME_RESERVED', 'This username is reserved.'],
    ['E_USERNAME_FORMAT', 'Enter a valid username.'],
    ['E_PASSWORD_LENGTH', 'Enter a password with the required length.'],
    ['E_PASSWORD_ASCII', 'Use only printable ASCII characters in the password.'],
    ['E_PASSWORD_USERNAME', 'The password cannot contain the username.'],
    ['E_PASSWORD_CLASS', 'Use the required mix of password character classes.'],
    ['E_PASSWORD_REPEAT', 'Avoid repeated characters in the password.'],
    ['E_PASSWORD_SEQUENCE', 'Avoid sequential characters in the password.'],
    ['E_PASSWORD_REUSE', 'The current or previous password cannot be reused.'],
    ['E_USER_DUPLICATE', 'That username already exists.'],
    ['E_VIEWER_LIMIT', 'The viewer account limit has been reached.'],
    ['E_USER_PROTECTED', 'This administrator account is protected.'],
    ['E_USER_CONFLICT', 'This account was changed. Refresh and try again.'],
    ['E_USER_NOT_FOUND', 'That account no longer exists.'],
    ['E_AUTHORIZATION_REQUIRED', 'You are not authorized to perform this action.'],
    ['E_MANAGEMENT_IP_INVALID', 'Enter one valid IPv4 or IPv6 host address.'],
    ['E_MANAGEMENT_IP_DUPLICATE', 'That address already exists for this role.'],
    ['E_MANAGEMENT_IP_LIMIT', 'The address limit for this role has been reached.'],
    ['E_MANAGEMENT_IP_PROTECTED', 'This administrator address is protected.'],
    ['E_MANAGEMENT_IP_ROLE_MISMATCH', 'That address belongs to a different role.'],
    ['E_MANAGEMENT_IP_NOT_FOUND', 'That address no longer exists.'],
    ['E_USER_MANAGEMENT_UNAVAILABLE', 'User management is temporarily unavailable.'],
  ])('maps %s without backend details', (code, expected) => {
    expect(userManagementErrorMessage(
      new ApiError(409, code, 'viewer-secret 192.0.2.44'),
      'Request failed.',
    )).toBe(expected);
  });

  it('uses bounded fallbacks and never exposes private details', () => {
    expect(userManagementErrorMessage(
      new UnauthorizedError('private-session-detail'), 'Request failed.',
    )).toBe('Your session has ended.');
    expect(userManagementErrorMessage(
      new ApiError(400, 'E_PRIVATE_AUTH_CODE', 'viewer-secret 192.0.2.44'),
      'Request failed.',
    )).toBe('Request failed.');
    expect(userManagementErrorMessage(
      new Error('viewer-secret 192.0.2.44'), 'Request failed.',
    )).toBe('Request failed.');
  });
});
