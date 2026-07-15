import { Check, RotateCcw, Save } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

import type {
  PublicApiError,
  RuntimeSettings,
  RuntimeSettingsSnapshot,
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
      draft.models.length !== snapshot.capabilities.models.length) {
    return false;
  }
  return draft.models.every((model, index) =>
    model.id === snapshot.capabilities.models[index]?.id &&
    typeof model.enabled === 'boolean' &&
    Number.isFinite(model.confidence_threshold) &&
    model.confidence_threshold >= 0 && model.confidence_threshold <= 1);
};

const errorText = (error: PublicApiError): string => {
  switch (error.code) {
    case 'E_SETTINGS_REVISION_CONFLICT':
      return 'Settings changed on the device. Review and save your changes again.';
    case 'E_SETTINGS_NO_PENDING':
      return 'There are no pending settings to apply or discard.';
    case 'E_SETTINGS_BUSY':
      return 'Another settings command is in progress.';
    case 'E_SETTINGS_UNSUPPORTED':
      return 'The selected runtime settings are not supported.';
    case 'E_SETTINGS_STORE':
      return 'Runtime settings could not be stored.';
    case 'E_SETTINGS_UNAVAILABLE':
      return 'Runtime settings are unavailable.';
    case 'E_SETTINGS_REQUEST_INVALID':
      return 'Runtime settings could not be validated.';
    case 'E_SETTINGS_APPLY_FAILED':
      return 'Settings could not be applied.';
    case 'E_SETTINGS_REQUEST_FAILED':
      return 'The settings request could not be completed.';
  }
};

const noticeFor = (controller: RuntimeSettingsController): {
  role: 'alert' | 'status';
  text: string;
} | null => {
  const { snapshot } = controller;
  if (snapshot?.last_apply.status === 'failed') {
    return snapshot.last_apply.restored
      ? { role: 'alert',
        text: 'Settings could not be applied. The previous runtime was restored.' }
      : { role: 'alert',
        text: 'Settings could not be applied and the camera runtime needs attention.' };
  }
  if (controller.error !== null) {
    return { role: 'alert', text: errorText(controller.error) };
  }
  if (snapshot?.state === 'recovery_required') {
    return { role: 'status',
      text: 'Save runtime settings to replace the invalid stored state.' };
  }
  if (snapshot?.pending !== null && snapshot?.pending !== undefined) {
    return { role: 'status', text: 'Saved settings are waiting to be applied.' };
  }
  return null;
};

export function SettingsActionBar({
  controller,
  onApplySettled = () => undefined,
}: SettingsActionBarProps) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const applyButtonRef = useRef<HTMLButtonElement>(null);
  const restoreApplyFocus = useRef(false);
  const busy = controller.status === 'saving' || controller.status === 'applying';
  const valid = isDraftValid(controller.draft, controller.snapshot);
  const hasPending = controller.snapshot?.pending !== null &&
    controller.snapshot?.pending !== undefined;
  const recoveryRequired = controller.snapshot?.state === 'recovery_required';
  const notice = noticeFor(controller);

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
      {notice !== null && (
        <p className={`settings-command-notice settings-command-${notice.role}`}
          role={notice.role}>{notice.text}</p>
      )}
      <div className="settings-action-bar" aria-label="Runtime settings actions">
        <span className="settings-revision">
          Revision {controller.snapshot?.revision ?? '-'}
        </span>
        <div>
          <button type="button" disabled={busy || !hasPending || controller.dirty}
            onClick={() => void controller.discard()}>
            <RotateCcw size={16} aria-hidden="true" />
            Discard pending
          </button>
          <button type="button"
            disabled={busy || (!controller.dirty && !recoveryRequired) || !valid}
            onClick={() => void controller.save()}>
            <Save size={16} aria-hidden="true" />
            Save changes
          </button>
          <button ref={applyButtonRef} className="settings-primary-action"
            type="button" disabled={busy || !hasPending || controller.dirty}
            aria-label={controller.status === 'applying'
              ? 'Applying settings'
              : 'Apply pending'}
            onClick={() => setDialogOpen(true)}>
            <Check size={16} aria-hidden="true" />
            {controller.status === 'applying' ? 'Applying...' : 'Apply pending'}
          </button>
        </div>
      </div>
      {dialogOpen && (
        <ApplySettingsDialog onCancel={cancelDialog} onConfirm={confirmApply} />
      )}
    </div>
  );
}
