import {
  type FormEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type RefObject,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import { X } from 'lucide-react';

import { ApiError } from '../../api/client';
import { IconButton } from '../../components/IconButton';

interface ChangePasswordDialogProps {
  open: boolean;
  returnFocusRef: RefObject<HTMLButtonElement>;
  changePassword(
    currentPassword: string,
    replacementPassword: string,
    signal?: AbortSignal,
  ): Promise<void>;
  onClose(): void;
}

interface SecretValues {
  currentPassword: string;
  replacementPassword: string;
  confirmation: string;
}

const GENERIC_FAILURE = 'Unable to change password.';
const MAX_PUBLIC_ERROR_CODE_LENGTH = 32;
const PUBLIC_PASSWORD_ERROR_CODES = new Set([
  'E_CURRENT_PASSWORD',
  'E_PASSWORD_REUSE',
  'E_INVALID_REQUEST',
]);

function validationError({ currentPassword, replacementPassword, confirmation }: SecretValues) {
  if (currentPassword.length === 0) {
    return 'Enter the current password.';
  }
  if (replacementPassword.length === 0) {
    return 'Enter a new password.';
  }
  if (confirmation.length === 0) {
    return 'Confirm the new password.';
  }
  if (replacementPassword !== confirmation) {
    return 'New passwords do not match.';
  }
  return null;
}

function publicError(error: unknown): string {
  return error instanceof ApiError && error.code.length <= MAX_PUBLIC_ERROR_CODE_LENGTH &&
      PUBLIC_PASSWORD_ERROR_CODES.has(error.code)
    ? error.code
    : GENERIC_FAILURE;
}

export function ChangePasswordDialog({
  open,
  returnFocusRef,
  changePassword,
  onClose,
}: ChangePasswordDialogProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [replacementPassword, setReplacementPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const currentInputRef = useRef<HTMLInputElement>(null);
  const replacementInputRef = useRef<HTMLInputElement>(null);
  const confirmationInputRef = useRef<HTMLInputElement>(null);
  const submitButtonRef = useRef<HTMLButtonElement>(null);
  const secretsRef = useRef<SecretValues>({
    currentPassword: '',
    replacementPassword: '',
    confirmation: '',
  });
  const activeController = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  const wasOpen = useRef(open);
  const openRef = useRef(open);
  openRef.current = open;

  const clearSecrets = useCallback(() => {
    secretsRef.current.currentPassword = '';
    secretsRef.current.replacementPassword = '';
    secretsRef.current.confirmation = '';
    if (mounted.current) {
      setCurrentPassword('');
      setReplacementPassword('');
      setConfirmation('');
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeController.current?.abort();
      activeController.current = null;
      clearSecrets();
    };
  }, [clearSecrets]);

  useEffect(() => {
    if (open) {
      setError(null);
      currentInputRef.current?.focus();
    } else {
      activeController.current?.abort();
      activeController.current = null;
      clearSecrets();
      setError(null);
      setPending(false);
      if (wasOpen.current) {
        returnFocusRef.current?.focus();
      }
    }
    wasOpen.current = open;
  }, [clearSecrets, open, returnFocusRef]);

  useEffect(() => {
    if (pending) {
      dialogRef.current?.focus();
    }
  }, [pending]);

  const close = useCallback(() => {
    if (pending) {
      return;
    }
    activeController.current?.abort();
    activeController.current = null;
    clearSecrets();
    setError(null);
    onClose();
    returnFocusRef.current?.focus();
  }, [clearSecrets, onClose, pending, returnFocusRef]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const validation = validationError(secretsRef.current);
    if (validation !== null) {
      clearSecrets();
      setError(validation);
      return;
    }

    const controller = new AbortController();
    activeController.current = controller;
    setError(null);
    setPending(true);
    let succeeded = false;
    const isCurrentRequest = () => mounted.current && openRef.current &&
      activeController.current === controller;
    try {
      await changePassword(
        secretsRef.current.currentPassword,
        secretsRef.current.replacementPassword,
        controller.signal,
      );
      succeeded = true;
    } catch (caught) {
      if (isCurrentRequest() && !controller.signal.aborted) {
        setError(publicError(caught));
      }
    } finally {
      if (!isCurrentRequest()) {
        return;
      }
      activeController.current = null;
      clearSecrets();
      if (!mounted.current) {
        return;
      }
      setPending(false);
      if (succeeded) {
        onClose();
        returnFocusRef.current?.focus();
      }
    }
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      close();
      return;
    }
    if (event.key !== 'Tab') {
      return;
    }
    event.preventDefault();
    if (pending) {
      dialogRef.current?.focus();
      return;
    }
    const focusable = [
      closeButtonRef.current,
      currentInputRef.current,
      replacementInputRef.current,
      confirmationInputRef.current,
      submitButtonRef.current,
    ].filter((element): element is HTMLButtonElement | HTMLInputElement => element !== null);
    const currentIndex = focusable.indexOf(document.activeElement as HTMLButtonElement);
    const nextIndex = event.shiftKey
      ? (currentIndex <= 0 ? focusable.length - 1 : currentIndex - 1)
      : (currentIndex === -1 || currentIndex === focusable.length - 1 ? 0 : currentIndex + 1);
    focusable[nextIndex]?.focus();
  };

  if (!open) {
    return null;
  }

  return (
    <div className="change-password-dialog-layer">
      <div ref={dialogRef} className="change-password-dialog" role="dialog" aria-modal="true"
        aria-labelledby="change-password-title" aria-describedby="change-password-error"
        tabIndex={-1} onKeyDown={onKeyDown}>
        <div className="change-password-dialog-header">
          <h2 id="change-password-title">Change password</h2>
          <IconButton ref={closeButtonRef} label="Close change password dialog" onClick={close}
            disabled={pending}>
            <X size={18} aria-hidden="true" />
          </IconButton>
        </div>
        <form onSubmit={(event) => void submit(event)} noValidate>
          <div className="field">
            <label htmlFor="change-password-current">Current password</label>
            <input
              ref={currentInputRef}
              id="change-password-current"
              name="current-password"
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              disabled={pending}
              aria-invalid={error !== null ? true : undefined}
              aria-describedby={error !== null ? 'change-password-error' : undefined}
              onChange={(event) => {
                const value = event.target.value;
                secretsRef.current.currentPassword = value;
                setCurrentPassword(value);
              }}
            />
          </div>
          <div className="field">
            <label htmlFor="change-password-new">New password</label>
            <input
              ref={replacementInputRef}
              id="change-password-new"
              name="new-password"
              type="password"
              autoComplete="new-password"
              value={replacementPassword}
              disabled={pending}
              aria-invalid={error !== null ? true : undefined}
              aria-describedby={error !== null ? 'change-password-error' : undefined}
              onChange={(event) => {
                const value = event.target.value;
                secretsRef.current.replacementPassword = value;
                setReplacementPassword(value);
              }}
            />
          </div>
          <div className="field">
            <label htmlFor="change-password-confirmation">Confirm new password</label>
            <input
              ref={confirmationInputRef}
              id="change-password-confirmation"
              name="confirmation"
              type="password"
              autoComplete="new-password"
              value={confirmation}
              disabled={pending}
              aria-invalid={error !== null ? true : undefined}
              aria-describedby={error !== null ? 'change-password-error' : undefined}
              onChange={(event) => {
                const value = event.target.value;
                secretsRef.current.confirmation = value;
                setConfirmation(value);
              }}
            />
          </div>
          <p id="change-password-error" className="change-password-error" role="alert"
            aria-live="assertive">
            {error ?? ''}
          </p>
          <div className="change-password-dialog-actions">
            <button ref={submitButtonRef} className="change-password-submit" type="submit"
              disabled={pending}>
              {pending ? 'Changing password...' : 'Change password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
