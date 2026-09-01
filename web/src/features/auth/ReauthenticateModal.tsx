import {
  type FormEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';

import { useTranslation } from '../../i18n/LanguageContext';

export interface ReauthenticateModalProps {
  reauthenticate: (password: string) => Promise<void>;
  onSuccess: () => void;
  onCancel: () => void;
}

export function ReauthenticateModal({
  reauthenticate,
  onSuccess,
  onCancel,
}: ReauthenticateModalProps) {
  const { t } = useTranslation();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const passwordInputRef = useRef<HTMLInputElement>(null);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);
  const confirmButtonRef = useRef<HTMLButtonElement>(null);
  const passwordRef = useRef('');
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    passwordInputRef.current?.focus();
    return () => {
      mounted.current = false;
    };
  }, []);

  const clearPassword = useCallback(() => {
    passwordRef.current = '';
    if (mounted.current) {
      setPassword('');
    }
  }, []);

  const cancel = useCallback(() => {
    if (pending) {
      return;
    }
    clearPassword();
    setError(null);
    onCancel();
  }, [clearPassword, onCancel, pending]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (passwordRef.current.length === 0) {
      setError(t('auth.enterPassword'));
      return;
    }

    setError(null);
    setPending(true);
    let succeeded = false;
    try {
      await reauthenticate(passwordRef.current);
      succeeded = true;
    } catch {
      if (mounted.current) {
        setError(t('auth.reauthFailed'));
      }
    } finally {
      clearPassword();
      if (!mounted.current) {
        return;
      }
      setPending(false);
      if (succeeded) {
        onSuccess();
      }
    }
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      cancel();
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
      passwordInputRef.current,
      cancelButtonRef.current,
      confirmButtonRef.current,
    ].filter((element): element is HTMLButtonElement | HTMLInputElement => element !== null);
    const currentIndex = focusable.indexOf(document.activeElement as HTMLButtonElement);
    const nextIndex = event.shiftKey
      ? (currentIndex <= 0 ? focusable.length - 1 : currentIndex - 1)
      : (currentIndex === -1 || currentIndex === focusable.length - 1 ? 0 : currentIndex + 1);
    focusable[nextIndex]?.focus();
  };

  return (
    <div className="change-password-dialog-layer">
      <div ref={dialogRef} className="change-password-dialog" role="dialog" aria-modal="true"
        aria-labelledby="reauthenticate-title" aria-describedby="reauthenticate-error"
        tabIndex={-1} onKeyDown={onKeyDown}>
        <div className="change-password-dialog-header">
          <h2 id="reauthenticate-title">{t('auth.reauthHeading')}</h2>
        </div>
        <p>{t('auth.reauthDescription')}</p>
        <form onSubmit={(event) => void submit(event)} noValidate>
          <div className="field">
            <label htmlFor="reauthenticate-password">{t('common.password')}</label>
            <input
              ref={passwordInputRef}
              id="reauthenticate-password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              disabled={pending}
              aria-invalid={error !== null ? true : undefined}
              aria-describedby={error !== null ? 'reauthenticate-error' : undefined}
              onChange={(event) => {
                const value = event.target.value;
                passwordRef.current = value;
                setPassword(value);
              }}
            />
          </div>
          <p id="reauthenticate-error" className="change-password-error" role="alert"
            aria-live="assertive">
            {error ?? ''}
          </p>
          <div className="reauthenticate-dialog-actions">
            <button ref={cancelButtonRef} className="reauthenticate-cancel" type="button"
              onClick={cancel} disabled={pending}>
              {t('common.cancel')}
            </button>
            <button ref={confirmButtonRef} className="change-password-submit" type="submit"
              disabled={pending} aria-busy={pending ? true : undefined}>
              {pending ? t('auth.confirming') : t('auth.confirm')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
