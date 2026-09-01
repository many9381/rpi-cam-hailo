import { AlertTriangle } from 'lucide-react';

import { useTranslation } from '../../i18n/LanguageContext';
import type { SystemProtectionController } from './useSystemProtection';

interface ProtectionNoticeProps {
  controller?: SystemProtectionController;
}

export function ProtectionNotice({ controller }: ProtectionNoticeProps) {
  const { t } = useTranslation();
  if (controller?.snapshot?.state !== 'restricted') {
    return null;
  }
  return (
    <div className="settings-shell-notice protection-shell-notice" role="alert">
      <span>
        <AlertTriangle size={17} aria-hidden="true" />
        {t('protection.restrictedNotice')}
      </span>
      <a href="#/system">{t('protection.reviewProtection')}</a>
    </div>
  );
}
