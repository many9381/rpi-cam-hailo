import {
  type KeyboardEvent as ReactKeyboardEvent,
  useEffect,
  useRef,
} from 'react';

import { useTranslation } from '../../i18n/LanguageContext';

interface ApplySettingsDialogProps {
  onCancel(): void;
  onConfirm(): void;
}

export function ApplySettingsDialog({
  onCancel,
  onConfirm,
}: ApplySettingsDialogProps) {
  const { t } = useTranslation();
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    cancelRef.current?.focus();
  }, []);

  const trapFocus = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      onCancel();
      return;
    }
    if (event.key !== 'Tab') {
      return;
    }
    if (event.shiftKey && document.activeElement === cancelRef.current) {
      event.preventDefault();
      confirmRef.current?.focus();
    } else if (!event.shiftKey && document.activeElement === confirmRef.current) {
      event.preventDefault();
      cancelRef.current?.focus();
    }
  };

  return (
    <div className="settings-dialog-layer">
      <button className="settings-dialog-backdrop" type="button"
        aria-label={t('settings.cancelApply')} tabIndex={-1} onClick={onCancel} />
      <div className="settings-dialog" role="alertdialog" aria-modal="true"
        aria-labelledby="apply-settings-title" aria-describedby="apply-settings-description"
        onKeyDown={trapFocus}>
        <h2 id="apply-settings-title">{t('settings.applyDialogTitle')}</h2>
        <p id="apply-settings-description">
          {t('settings.applyDialogDescription')}
        </p>
        <div className="settings-dialog-actions">
          <button ref={cancelRef} type="button" onClick={onCancel}>{t('common.cancel')}</button>
          <button ref={confirmRef} className="settings-primary-action" type="button"
            onClick={onConfirm}>{t('settings.applyNow')}</button>
        </div>
      </div>
    </div>
  );
}
