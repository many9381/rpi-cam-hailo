import { ApiError } from '../../api/client';
import type { useTranslation } from '../../i18n/LanguageContext';

type TFunc = ReturnType<typeof useTranslation>['t'];

export function auditErrorMessage(error: unknown, t: TFunc): string {
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'E_AUDIT_QUERY_INVALID':
        return t('errors.auditQueryInvalid');
      case 'E_AUDIT_UNAVAILABLE':
        return t('audit.recordsUnavailable');
    }
  }
  return t('errors.auditRequestFailed');
}
