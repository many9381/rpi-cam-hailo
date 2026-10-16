import { ApiError, UnauthorizedError } from '../../api/client';
import type { useTranslation } from '../../i18n/LanguageContext';

type TFunc = ReturnType<typeof useTranslation>['t'];

// Translation keys, not English text: userManagementErrorMessage takes `t`
// and resolves through the caller's active language. See errors.* in
// src/i18n/messages/en.ts for the source English text of each key.
const messageKeys: Readonly<Record<string, string>> = {
  E_USERNAME_RESERVED: 'errors.usernameReserved',
  E_USERNAME_FORMAT: 'errors.usernameInvalid',
  E_PASSWORD_LENGTH: 'errors.passwordLengthRequired',
  E_PASSWORD_ASCII: 'errors.passwordAsciiOnly',
  E_PASSWORD_USERNAME: 'errors.passwordContainsUsername',
  E_PASSWORD_CLASS: 'errors.passwordClassMix',
  E_PASSWORD_REPEAT: 'errors.passwordRepeatedChars',
  E_PASSWORD_SEQUENCE: 'errors.passwordSequentialChars',
  E_PASSWORD_REUSE: 'errors.passwordReused',
  E_CURRENT_PASSWORD: 'errors.currentPasswordIncorrect',
  E_USER_DUPLICATE: 'errors.usernameExists',
  E_VIEWER_LIMIT: 'errors.viewerLimitReached',
  E_USER_PROTECTED: 'errors.userProtected',
  E_USER_CONFLICT: 'errors.userConflict',
  E_USER_NOT_FOUND: 'errors.userNotFound',
  E_AUTHORIZATION_REQUIRED: 'errors.notAuthorized',
  E_MANAGEMENT_IP_LOCKOUT: 'errors.managementIpLockout',
  E_MANAGEMENT_IP_INVALID: 'errors.managementIpInvalid',
  E_MANAGEMENT_IP_DUPLICATE: 'errors.managementIpExists',
  E_MANAGEMENT_IP_LIMIT: 'errors.managementIpLimitReached',
  E_MANAGEMENT_IP_PROTECTED: 'errors.managementIpProtected',
  E_MANAGEMENT_IP_ROLE_MISMATCH: 'errors.managementIpRoleMismatch',
  E_MANAGEMENT_IP_NOT_FOUND: 'errors.managementIpNotFound',
  E_USER_MANAGEMENT_UNAVAILABLE: 'errors.userManagementUnavailable',
};

export function userManagementErrorMessage(error: unknown, fallback: string, t: TFunc): string {
  if (error instanceof UnauthorizedError) {
    return t('errors.sessionEnded');
  }
  if (error instanceof ApiError) {
    const key = messageKeys[error.code];
    return key ? t(key) : fallback;
  }
  return fallback;
}
