import {
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type RefObject,
  useEffect,
  useId,
  useRef,
} from 'react';
import { X } from 'lucide-react';

import { IconButton } from '../../components/IconButton';
import { useTranslation } from '../../i18n/LanguageContext';

const FOCUSABLE_SELECTOR = 'button:not([disabled]), input:not([disabled]), select:not([disabled]), [href]';

export interface UserManagementDialogProps {
  title: string;
  description?: string;
  pending: boolean;
  destructive?: boolean;
  returnFocusRef: RefObject<HTMLElement>;
  children: ReactNode;
  onClose(): void;
}

export function UserManagementDialog({
  title,
  description,
  pending,
  destructive = false,
  returnFocusRef,
  children,
  onClose,
}: UserManagementDialogProps) {
  const { t } = useTranslation();
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    if (pending) {
      dialogRef.current?.focus();
      return;
    }
    closeButtonRef.current?.focus();
  }, [pending]);

  useEffect(() => () => {
    if (returnFocusRef.current?.isConnected) {
      returnFocusRef.current.focus();
    }
  }, [returnFocusRef]);

  const requestClose = () => {
    if (pending) {
      dialogRef.current?.focus();
      return;
    }
    onClose();
  };

  const trapFocus = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      requestClose();
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

    const focusable = Array.from(
      dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR) ?? [],
    );
    const currentIndex = focusable.indexOf(document.activeElement as HTMLElement);
    const nextIndex = event.shiftKey
      ? (currentIndex <= 0 ? focusable.length - 1 : currentIndex - 1)
      : (currentIndex === -1 || currentIndex === focusable.length - 1 ? 0 : currentIndex + 1);
    focusable[nextIndex]?.focus();
  };

  return (
    <div className="user-management-dialog-layer">
      <button
        className="user-management-dialog-backdrop"
        type="button"
        aria-label={t('users.closeDialog')}
        tabIndex={-1}
        onClick={requestClose}
      />
      <div
        ref={dialogRef}
        className="user-management-dialog"
        role={destructive ? 'alertdialog' : 'dialog'}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description === undefined ? undefined : descriptionId}
        tabIndex={-1}
        onKeyDown={trapFocus}
      >
        <div className="user-management-dialog-header">
          <h2 id={titleId}>{title}</h2>
          <IconButton
            ref={closeButtonRef}
            label={t('users.closeDialogWithTitle', { title })}
            onClick={requestClose}
            disabled={pending}
          >
            <X size={18} aria-hidden="true" />
          </IconButton>
        </div>
        {description !== undefined && <p id={descriptionId}>{description}</p>}
        {children}
      </div>
    </div>
  );
}
