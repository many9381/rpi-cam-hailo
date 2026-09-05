import { Check, RotateCcw, Save } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import { useTranslation } from '../../i18n/LanguageContext';
import {
  isOsdSettingsValid,
  type RuntimeSettings,
  type RuntimeSettingsErrorCode,
  type RuntimeSettingsSnapshot,
} from './contracts';
import { ApplySettingsDialog } from './ApplySettingsDialog';
import type { RuntimeSettingsController } from './useRuntimeSettings';

interface SettingsActionBarProps {
  controller: RuntimeSettingsController;
  onApplySettled?: () => void;
}

const isDraftValid = (
  draft: RuntimeSettings | null,
  snapshot: RuntimeSettingsSnapshot | null,
): boolean => {
  if (draft === null || snapshot === null ||
      !snapshot.capabilities.camera_profiles.some(
        ({ id }) => id === draft.camera.profile_id,
      ) || !Number.isSafeInteger(draft.camera.bitrate_kbps) ||
      draft.camera.bitrate_kbps < snapshot.capabilities.bitrate_kbps.minimum ||
      draft.camera.bitrate_kbps > snapshot.capabilities.bitrate_kbps.maximum ||
      !Number.isSafeInteger(draft.camera.gop) ||
      draft.camera.gop < snapshot.capabilities.gop.minimum ||
      draft.camera.gop > snapshot.capabilities.gop.maximum ||
      draft.models.length !== snapshot.capabilities.models.length ||
      !isOsdSettingsValid(draft.osd)) {
    return false;
  }
  return draft.models.every((model, index) =>
    model.id === snapshot.capabilities.models[index]?.id &&
    typeof model.enabled === 'boolean' &&
    Number.isFinite(model.confidence_threshold) &&
    model.confidence_threshold >= 0 && model.confidence_threshold <= 1);
};

const errorTextKeys: Record<RuntimeSettingsErrorCode, string> = {
  E_SETTINGS_REVISION_CONFLICT: 'settings.errorRevisionConflict',
  E_SETTINGS_NO_PENDING: 'settings.errorNoPending',
  E_SETTINGS_BUSY: 'settings.errorBusy',
  E_SETTINGS_UNSUPPORTED: 'settings.errorUnsupported',
  E_SETTINGS_STORE: 'settings.errorStore',
  E_SETTINGS_UNAVAILABLE: 'settings.unavailable',
  E_SETTINGS_REQUEST_INVALID: 'settings.errorRequestInvalid',
  E_SETTINGS_APPLY_FAILED: 'settings.errorApplyFailed',
  E_SETTINGS_REQUEST_FAILED: 'settings.errorRequestFailed',
};

const noticeKeyFor = (controller: RuntimeSettingsController): {
  role: 'alert' | 'status';
  key: string;
} | null => {
  const { snapshot } = controller;
  if (snapshot?.last_apply.status === 'failed') {
    return snapshot.last_apply.restored
      ? { role: 'alert', key: 'settings.noticeApplyFailedRestored' }
      : { role: 'alert', key: 'settings.noticeApplyFailedNeedsAttention' };
  }
  if (controller.error !== null) {
    return { role: 'alert', key: errorTextKeys[controller.error.code] };
  }
  if (snapshot?.state === 'recovery_required') {
    return { role: 'status', key: 'settings.noticeRecoveryRequired' };
  }
  if (snapshot?.pending !== null && snapshot?.pending !== undefined) {
    return { role: 'status', key: 'settings.noticePendingSaved' };
  }
  return null;
};

export function SettingsActionBar({
  controller,
  onApplySettled = () => undefined,
}: SettingsActionBarProps) {
  const { t } = useTranslation();
  const [dialogOpen, setDialogOpen] = useState(false);
  const applyButtonRef = useRef<HTMLButtonElement>(null);
  const restoreApplyFocus = useRef(false);
  const busy = controller.status === 'saving' || controller.status === 'applying';
  const valid = isDraftValid(controller.draft, controller.snapshot);
  const hasPending = controller.snapshot?.pending !== null &&
    controller.snapshot?.pending !== undefined;
  const recoveryRequired = controller.snapshot?.state === 'recovery_required';
  const noticeKey = noticeKeyFor(controller);

  useEffect(() => {
    if (!dialogOpen && restoreApplyFocus.current) {
      restoreApplyFocus.current = false;
      applyButtonRef.current?.focus();
    }
  }, [dialogOpen]);

  const cancelDialog = () => {
    restoreApplyFocus.current = true;
    setDialogOpen(false);
  };

  const confirmApply = () => {
    setDialogOpen(false);
    void controller.apply().finally(onApplySettled);
  };

  return (
    <div className="settings-actions-wrap">
      {noticeKey !== null && (
        <p className={`settings-command-notice settings-command-${noticeKey.role}`}
          role={noticeKey.role}>{t(noticeKey.key)}</p>
      )}
      <div className="settings-action-bar" aria-label={t('settings.actionsLabel')}>
        <span className="settings-revision">
          {t('settings.revisionLabel', { revision: controller.snapshot?.revision ?? '-' })}
        </span>
        <div>
          <button type="button" disabled={busy || !hasPending || controller.dirty}
            onClick={() => void controller.discard()}>
            <RotateCcw size={16} aria-hidden="true" />
            {t('settings.discardPending')}
          </button>
          <button type="button"
            disabled={busy || (!controller.dirty && !recoveryRequired) || !valid}
            onClick={() => void controller.save()}>
            <Save size={16} aria-hidden="true" />
            {t('settings.saveChanges')}
          </button>
          <button ref={applyButtonRef} className="settings-primary-action"
            type="button" disabled={busy || !hasPending || controller.dirty}
            aria-label={controller.status === 'applying'
              ? t('settings.applyingSettings')
              : t('settings.applyPending')}
            onClick={() => setDialogOpen(true)}>
            <Check size={16} aria-hidden="true" />
            {controller.status === 'applying' ? t('settings.applying') : t('settings.applyPending')}
          </button>
        </div>
      </div>
      {dialogOpen && (
        <ApplySettingsDialog onCancel={cancelDialog} onConfirm={confirmApply} />
      )}
    </div>
  );
}
