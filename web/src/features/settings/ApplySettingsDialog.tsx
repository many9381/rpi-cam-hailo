import {
  type KeyboardEvent as ReactKeyboardEvent,
  useEffect,
  useRef,
} from 'react';

interface ApplySettingsDialogProps {
  onCancel(): void;
  onConfirm(): void;
}

export function ApplySettingsDialog({
  onCancel,
  onConfirm,
}: ApplySettingsDialogProps) {
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
        aria-label="Cancel apply" tabIndex={-1} onClick={onCancel} />
      <div className="settings-dialog" role="alertdialog" aria-modal="true"
        aria-labelledby="apply-settings-title" aria-describedby="apply-settings-description"
        onKeyDown={trapFocus}>
        <h2 id="apply-settings-title">Apply runtime settings</h2>
        <p id="apply-settings-description">
          Camera video and RTSP clients will reconnect briefly. Management access
          remains available.
        </p>
        <div className="settings-dialog-actions">
          <button ref={cancelRef} type="button" onClick={onCancel}>Cancel</button>
          <button ref={confirmRef} className="settings-primary-action" type="button"
            onClick={onConfirm}>Apply now</button>
        </div>
      </div>
    </div>
  );
}
