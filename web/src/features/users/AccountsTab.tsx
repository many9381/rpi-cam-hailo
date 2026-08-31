import {
  type FormEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react';
import { KeyRound, Trash2 } from 'lucide-react';

import { IconButton } from '../../components/IconButton';
import { useTranslation } from '../../i18n/LanguageContext';
import {
  type SetupCredentialErrors,
  validateSetupCredentials,
} from '../../security/setupPolicy';
import type { ManagedUser } from './contracts';
import { userManagementErrorMessage } from './publicError';
import { UserManagementDialog } from './UserManagementDialog';
import type {
  UserManagementCommandResult,
  UserManagementController,
} from './useUserManagement';

interface AccountsTabProps {
  controller: UserManagementController;
  createOpen: boolean;
  onCreateClose(): void;
}

type AccountDialog = {
  kind: 'enable' | 'disable' | 'reset' | 'delete';
  user: ManagedUser;
};

type TFunc = ReturnType<typeof useTranslation>['t'];

const REFRESH_FAILURE_NOTICE_KEY = 'users.accountRefreshFailedNotice';

const fallbackKeyByAction = {
  enable: 'users.enableViewerFailed',
  disable: 'users.disableViewerFailed',
  reset: 'users.resetViewerPasswordFailed',
  delete: 'users.deleteViewerFailed',
} as const;

const ROLE_LABEL_KEYS: Record<ManagedUser['role'], string> = {
  administrator: 'users.roleAdministrator',
  viewer: 'users.roleViewer',
};

type AccountConfirmKind = 'enable' | 'disable' | 'delete';

const ACCOUNT_ACTION_TITLE_KEYS: Record<AccountConfirmKind, string> = {
  enable: 'users.enableViewer',
  disable: 'users.disableViewer',
  delete: 'users.deleteViewer',
};

const ACCOUNT_ACTION_PENDING_KEYS: Record<AccountConfirmKind, string> = {
  enable: 'users.enablingViewer',
  disable: 'users.disablingViewer',
  delete: 'users.deletingViewer',
};

const ACCOUNT_ACTION_DESCRIPTION_KEYS: Record<AccountConfirmKind, string> = {
  enable: 'users.enableViewerDescription',
  disable: 'users.disableViewerDescription',
  delete: 'users.deleteViewerDescription',
};

function formatTimestamp(seconds: number): string {
  return new Intl.DateTimeFormat().format(new Date(seconds * 1_000));
}

function accountStatusText(user: ManagedUser, t: TFunc): string {
  if (!user.enabled) {
    return t('ai.disabled');
  }
  if (user.lock_until_seconds !== null) {
    return t('users.lockedUntil', {
      timestamp: formatTimestamp(user.lock_until_seconds),
    });
  }
  return t('users.accountEnabled');
}

export function AccountsTab({
  controller,
  createOpen,
  onCreateClose,
}: AccountsTabProps) {
  const { t } = useTranslation();
  const [dialog, setDialog] = useState<AccountDialog | null>(null);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [credentialErrors, setCredentialErrors] = useState<SetupCredentialErrors>({});
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const passwordRef = useRef('');
  const confirmationRef = useRef('');
  const createReturnFocusRef = useRef<HTMLElement | null>(null);
  const actionReturnFocusRef = useRef<HTMLElement | null>(null);
  const activeSubmission = useRef<object | null>(null);
  const mounted = useRef(false);
  const createWasOpen = useRef(false);

  const clearSecrets = useCallback(() => {
    passwordRef.current = '';
    confirmationRef.current = '';
    if (mounted.current) {
      setPassword('');
      setConfirmation('');
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeSubmission.current = null;
      passwordRef.current = '';
      confirmationRef.current = '';
    };
  }, []);

  useLayoutEffect(() => {
    const wasOpen = createWasOpen.current;
    if (createOpen && !wasOpen) {
      const activeElement = document.activeElement;
      createReturnFocusRef.current = activeElement instanceof HTMLElement &&
          activeElement.isConnected
        ? activeElement
        : null;
      clearSecrets();
      setUsername('');
      setCredentialErrors({});
      setDialogError(null);
    } else if (!createOpen && wasOpen) {
      activeSubmission.current = null;
      clearSecrets();
      setUsername('');
      setCredentialErrors({});
      setDialogError(null);
      setSubmitting(false);
    }
    createWasOpen.current = createOpen;
  }, [clearSecrets, createOpen]);

  const pending = submitting || controller.mutation !== null;

  const finishSuccess = (
    result: UserManagementCommandResult,
    close: () => void,
  ) => {
    if (!mounted.current) {
      return;
    }
    setDialogError(null);
    if (!result.refreshed) {
      setNotice(t(REFRESH_FAILURE_NOTICE_KEY));
    }
    close();
  };

  const closeCreate = () => {
    if (pending) {
      return;
    }
    activeSubmission.current = null;
    clearSecrets();
    setUsername('');
    setCredentialErrors({});
    setDialogError(null);
    onCreateClose();
  };

  const closeAction = () => {
    if (pending) {
      return;
    }
    activeSubmission.current = null;
    clearSecrets();
    setCredentialErrors({});
    setDialogError(null);
    setDialog(null);
  };

  const beginSubmission = (): object | null => {
    if (activeSubmission.current !== null || controller.mutation !== null) {
      return null;
    }
    const token = {};
    activeSubmission.current = token;
    setSubmitting(true);
    setDialogError(null);
    setNotice(null);
    return token;
  };

  const isCurrentSubmission = (token: object) =>
    mounted.current && activeSubmission.current === token;

  const endSubmission = (token: object) => {
    if (!isCurrentSubmission(token)) {
      return;
    }
    activeSubmission.current = null;
    setSubmitting(false);
  };

  const submitCreate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const validation = validateSetupCredentials(
      username,
      passwordRef.current,
      confirmationRef.current,
    );
    setCredentialErrors(validation);
    setDialogError(null);
    if (Object.keys(validation).length > 0) {
      clearSecrets();
      return;
    }

    const token = beginSubmission();
    if (token === null) {
      return;
    }
    const submittedPassword = passwordRef.current;
    clearSecrets();
    try {
      const result = await controller.createViewer(username, submittedPassword);
      if (!isCurrentSubmission(token)) {
        return;
      }
      clearSecrets();
      setUsername('');
      setCredentialErrors({});
      activeSubmission.current = null;
      setSubmitting(false);
      finishSuccess(result, onCreateClose);
    } catch (error) {
      if (!isCurrentSubmission(token)) {
        return;
      }
      clearSecrets();
      setDialogError(userManagementErrorMessage(
        error,
        t('users.viewerCreateFailed'),
      ));
      endSubmission(token);
    }
  };

  const openAction = (
    nextDialog: AccountDialog,
    opener: HTMLElement,
  ) => {
    if (pending) {
      return;
    }
    actionReturnFocusRef.current = opener;
    clearSecrets();
    setCredentialErrors({});
    setDialogError(null);
    setNotice(null);
    setDialog(nextDialog);
  };

  const submitConfirmation = async () => {
    if (dialog === null || dialog.kind === 'reset') {
      return;
    }
    const token = beginSubmission();
    if (token === null) {
      return;
    }
    const currentDialog = dialog;
    try {
      const result = currentDialog.kind === 'delete'
        ? await controller.deleteViewer(currentDialog.user.id)
        : await controller.setViewerEnabled(
          currentDialog.user.id,
          currentDialog.kind === 'enable',
        );
      if (!isCurrentSubmission(token)) {
        return;
      }
      activeSubmission.current = null;
      setSubmitting(false);
      finishSuccess(result, () => setDialog(null));
    } catch (error) {
      if (!isCurrentSubmission(token)) {
        return;
      }
      setDialogError(userManagementErrorMessage(
        error,
        t(fallbackKeyByAction[currentDialog.kind]),
      ));
      endSubmission(token);
    }
  };

  const submitReset = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (dialog?.kind !== 'reset') {
      return;
    }
    const validation = validateSetupCredentials(
      dialog.user.username,
      passwordRef.current,
      confirmationRef.current,
    );
    const passwordErrors: SetupCredentialErrors = {
      password: validation.password,
      confirmation: validation.confirmation,
    };
    if (passwordErrors.password === undefined) {
      delete passwordErrors.password;
    }
    if (passwordErrors.confirmation === undefined) {
      delete passwordErrors.confirmation;
    }
    setCredentialErrors(passwordErrors);
    setDialogError(null);
    if (Object.keys(passwordErrors).length > 0) {
      clearSecrets();
      return;
    }

    const token = beginSubmission();
    if (token === null) {
      return;
    }
    const target = dialog.user;
    const submittedPassword = passwordRef.current;
    clearSecrets();
    try {
      const result = await controller.resetViewerPassword(
        target.id,
        submittedPassword,
      );
      if (!isCurrentSubmission(token)) {
        return;
      }
      clearSecrets();
      setCredentialErrors({});
      activeSubmission.current = null;
      setSubmitting(false);
      finishSuccess(result, () => setDialog(null));
    } catch (error) {
      if (!isCurrentSubmission(token)) {
        return;
      }
      clearSecrets();
      setDialogError(userManagementErrorMessage(error, t(fallbackKeyByAction.reset)));
      endSubmission(token);
    }
  };

  const credentialFields = (reset: boolean) => (
    <>
      <div className="field">
        <label htmlFor={reset ? 'viewer-reset-password' : 'viewer-create-password'}>
          {reset ? t('users.newPassword') : t('common.password')}
        </label>
        <input
          id={reset ? 'viewer-reset-password' : 'viewer-create-password'}
          name="password"
          type="password"
          autoComplete="new-password"
          minLength={9}
          maxLength={128}
          value={password}
          disabled={pending}
          aria-invalid={credentialErrors.password ? true : undefined}
          aria-describedby={credentialErrors.password
            ? (reset ? 'viewer-reset-password-error' : 'viewer-create-password-error')
            : undefined}
          onChange={(event) => {
            passwordRef.current = event.target.value;
            setPassword(event.target.value);
          }}
        />
        {credentialErrors.password && (
          <p
            id={reset ? 'viewer-reset-password-error' : 'viewer-create-password-error'}
            className="form-error"
          >
            {credentialErrors.password}
          </p>
        )}
      </div>
      <div className="field">
        <label htmlFor={reset ? 'viewer-reset-confirmation' : 'viewer-create-confirmation'}>
          {reset ? t('users.confirmNewPassword') : t('setup.confirmPassword')}
        </label>
        <input
          id={reset ? 'viewer-reset-confirmation' : 'viewer-create-confirmation'}
          name="confirmation"
          type="password"
          autoComplete="new-password"
          minLength={9}
          maxLength={128}
          value={confirmation}
          disabled={pending}
          aria-invalid={credentialErrors.confirmation ? true : undefined}
          aria-describedby={credentialErrors.confirmation
            ? (reset ? 'viewer-reset-confirmation-error' : 'viewer-create-confirmation-error')
            : undefined}
          onChange={(event) => {
            confirmationRef.current = event.target.value;
            setConfirmation(event.target.value);
          }}
        />
        {credentialErrors.confirmation && (
          <p
            id={reset
              ? 'viewer-reset-confirmation-error'
              : 'viewer-create-confirmation-error'}
            className="form-error"
          >
            {credentialErrors.confirmation}
          </p>
        )}
      </div>
    </>
  );

  const renderResource = () => {
    const { users } = controller;
    if (users.status === 'loading' && users.data.length === 0) {
      return <p className="user-management-resource-state">{t('users.loadingAccounts')}</p>;
    }
    if (users.status === 'error') {
      return (
        <div className="user-management-resource-state">
          <p role="alert">
            {userManagementErrorMessage(
              users.error,
              t('users.accountListLoadFailed'),
            )}
          </p>
          <button
            type="button"
            disabled={controller.mutation !== null}
            onClick={() => void controller.refreshUsers().catch(() => undefined)}
          >
            {t('users.retryAccounts')}
          </button>
        </div>
      );
    }
    if (users.data.length === 0) {
      return <p className="user-management-resource-state">{t('users.noAccounts')}</p>;
    }

    return (
      <div className="accounts-tab">
        <table className="user-management-table accounts-table">
          <thead>
            <tr>
              <th scope="col">{t('users.user')}</th>
              <th scope="col">{t('users.role')}</th>
              <th scope="col">{t('users.status')}</th>
              <th scope="col">{t('users.lastLogin')}</th>
              <th className="account-actions-column" scope="col">{t('users.actions')}</th>
            </tr>
          </thead>
          <tbody>
            {users.data.map((user) => (
              <tr key={user.id}>
                <td data-label={t('users.user')}>{user.username}</td>
                <td data-label={t('users.role')}>
                  {t(ROLE_LABEL_KEYS[user.role])}
                </td>
                <td data-label={t('users.status')}>{accountStatusText(user, t)}</td>
                <td data-label={t('users.lastLogin')}>
                  {user.last_login_at_seconds === null
                    ? t('common.never')
                    : formatTimestamp(user.last_login_at_seconds)}
                </td>
                <td className="account-actions-cell" data-label={t('users.actions')}>
                  {user.role === 'viewer' && (
                    <div className="account-actions">
                      <label className="switch-control">
                        <input
                          type="checkbox"
                          role="switch"
                          aria-label={t(
                            user.enabled ? 'users.disableUsername' : 'users.enableUsername',
                            { username: user.username },
                          )}
                          checked={user.enabled}
                          disabled={pending}
                          onChange={(event) => openAction({
                            kind: user.enabled ? 'disable' : 'enable',
                            user,
                          }, event.currentTarget)}
                        />
                        <span aria-hidden="true" />
                      </label>
                      <IconButton
                        label={t('users.resetPasswordFor', { username: user.username })}
                        disabled={pending}
                        onClick={(event) => openAction({ kind: 'reset', user }, event.currentTarget)}
                      >
                        <KeyRound size={18} aria-hidden="true" />
                      </IconButton>
                      <IconButton
                        label={t('users.deleteUsername', { username: user.username })}
                        disabled={pending}
                        onClick={(event) => openAction({ kind: 'delete', user }, event.currentTarget)}
                      >
                        <Trash2 size={18} aria-hidden="true" />
                      </IconButton>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <>
      {notice !== null && (
        <p className="user-management-resource-warning" role="status">{notice}</p>
      )}
      {controller.users.status === 'stale' && (
        <p className="user-management-resource-warning" role="alert">
          {t('users.accountListRefreshFailed')}
        </p>
      )}
      {renderResource()}

      {createOpen && (
        <UserManagementDialog
          title={t('users.addViewer')}
          description={t('users.addViewerDescription')}
          pending={pending}
          returnFocusRef={createReturnFocusRef}
          onClose={closeCreate}
        >
          <form className="user-management-dialog-form" onSubmit={(event) => void submitCreate(event)} noValidate>
            <div className="field">
              <label htmlFor="viewer-create-username">{t('common.username')}</label>
              <input
                id="viewer-create-username"
                name="username"
                autoComplete="username"
                minLength={5}
                maxLength={32}
                value={username}
                disabled={pending}
                aria-invalid={credentialErrors.username ? true : undefined}
                aria-describedby={credentialErrors.username
                  ? 'viewer-create-username-error'
                  : undefined}
                onChange={(event) => setUsername(event.target.value)}
              />
              {credentialErrors.username && (
                <p id="viewer-create-username-error" className="form-error">
                  {credentialErrors.username}
                </p>
              )}
            </div>
            {credentialFields(false)}
            {dialogError !== null && <p className="form-error" role="alert">{dialogError}</p>}
            <div className="user-management-dialog-actions">
              <button className="primary-button" type="submit" disabled={pending}>
                {submitting ? t('users.creatingViewer') : t('users.createViewer')}
              </button>
            </div>
          </form>
        </UserManagementDialog>
      )}

      {dialog?.kind === 'reset' && (
        <UserManagementDialog
          title={t('users.resetViewerPasswordTitle')}
          description={t('users.resetPasswordDescription', {
            username: dialog.user.username,
          })}
          pending={pending}
          returnFocusRef={actionReturnFocusRef}
          onClose={closeAction}
        >
          <form className="user-management-dialog-form" onSubmit={(event) => void submitReset(event)} noValidate>
            {credentialFields(true)}
            {dialogError !== null && <p className="form-error" role="alert">{dialogError}</p>}
            <div className="user-management-dialog-actions">
              <button className="primary-button" type="submit" disabled={pending}>
                {submitting ? t('users.resettingPassword') : t('users.resetPassword')}
              </button>
            </div>
          </form>
        </UserManagementDialog>
      )}

      {dialog !== null && dialog.kind !== 'reset' && (
        <UserManagementDialog
          title={t(ACCOUNT_ACTION_TITLE_KEYS[dialog.kind])}
          description={t(ACCOUNT_ACTION_DESCRIPTION_KEYS[dialog.kind], {
            username: dialog.user.username,
          })}
          pending={pending}
          destructive={dialog.kind === 'delete'}
          returnFocusRef={actionReturnFocusRef}
          onClose={closeAction}
        >
          {dialogError !== null && <p className="form-error" role="alert">{dialogError}</p>}
          <div className="user-management-dialog-actions">
            <button
              className={dialog.kind === 'delete' ? 'danger-button' : 'primary-button'}
              type="button"
              disabled={pending}
              onClick={() => void submitConfirmation()}
            >
              {submitting
                ? t(ACCOUNT_ACTION_PENDING_KEYS[dialog.kind])
                : t(ACCOUNT_ACTION_TITLE_KEYS[dialog.kind])}
            </button>
          </div>
        </UserManagementDialog>
      )}
    </>
  );
}
