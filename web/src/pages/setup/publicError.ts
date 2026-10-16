import { ApiError } from '../../api/client';
import type { useTranslation } from '../../i18n/LanguageContext';

const validationKeys: Readonly<Record<string, string>> = {
  E_USERNAME_RESERVED: 'errors.usernameReserved',
  E_USERNAME_FORMAT: 'errors.usernameInvalid',
  E_PASSWORD_LENGTH: 'errors.passwordLengthRequired',
  E_PASSWORD_ASCII: 'errors.passwordAsciiOnly',
  E_PASSWORD_USERNAME: 'errors.passwordDiffersFromUsername',
  E_PASSWORD_CLASS: 'errors.passwordClassMix',
  E_PASSWORD_REPEAT: 'errors.passwordRepeatedChars',
  E_PASSWORD_SEQUENCE: 'errors.passwordSequentialChars',
  E_MANAGEMENT_IP_INVALID: 'errors.managementIpInvalid',
  E_MANAGEMENT_IP_LIMIT: 'errors.managementIpLimitReached',
  E_BOOTSTRAP_PEER: 'setup.peerChanged',
};

export function setupErrorMessage(
  error: unknown,
  t: ReturnType<typeof useTranslation>['t'],
): string {
  // Only public, known errors select text. Never echo server/transport details.
  if (error instanceof ApiError) {
    if (error.status === 401) return t('setup.sessionEnded');
    if (error.status === 429) return t('setup.rateLimited');
    if (error.status >= 500) return t('setup.serviceUnavailable');
    if (error.code === 'E_REQUEST_ORIGIN') return t('auth.requestOriginFailed');
    if (error.status === 400) {
      return t(Object.prototype.hasOwnProperty.call(validationKeys, error.code)
        ? validationKeys[error.code]
        : 'setup.requestInvalid');
    }
  }
  return t('setup.initializationFailed');
}
