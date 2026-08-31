import { useTranslation } from '../../i18n/LanguageContext';
import type { AuditStatusController } from './useAuditStatus';

interface AuditCapacityNoticeProps {
  controller?: AuditStatusController;
}

export function AuditCapacityNotice({ controller }: AuditCapacityNoticeProps) {
  const { t } = useTranslation();
  const status = controller?.data;
  if (status === null || status === undefined || !status.warning) {
    return null;
  }

  return (
    <div className="settings-shell-notice audit-capacity-notice" role="alert">
      <span>
        {t('audit.storageNotice', {
          percent: status.usage_percent,
          current: status.current_events,
          max: status.max_events,
        })}
        {controller?.state === 'stale' && ` ${t('audit.capacityStale')}`}
      </span>
      <a href="#/system#audit-records">{t('audit.reviewRecords')}</a>
    </div>
  );
}
