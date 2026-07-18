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

const REFRESH_FAILURE_NOTICE =
  'Changes were applied, but the account list could not be refreshed.';

const fallbackByAction = {
  enable: 'The viewer could not be enabled.',
  disable: 'The viewer could not be disabled.',
  reset: 'The viewer password could not be reset.',
  delete: 'The viewer could not be deleted.',
} as const;

function formatTimestamp(seconds: number | null): string {
  if (seconds === null) {
    return 'Never';
  }
  return new Intl.DateTimeFormat().format(new Date(seconds * 1_000));
}

function accountStatus(user: ManagedUser): string {
  if (!user.enabled) {
    return 'Disabled';
  }
  if (user.lock_until_seconds !== null) {
    return `Locked until ${formatTimestamp(user.lock_until_seconds)}`;
  }
  return 'Enabled';
}

export function AccountsTab({
  controller,
  createOpen,
  onCreateClose,
}: AccountsTabProps) {
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
      setNotice(REFRESH_FAILURE_NOTICE);
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
        'The viewer could not be created.',
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
        fallbackByAction[currentDialog.kind],
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
      setDialogError(userManagementErrorMessage(error, fallbackByAction.reset));
      endSubmission(token);
    }
  };

  const credentialFields = (reset: boolean) => (
    <>
      <div className="field">
        <label htmlFor={reset ? 'viewer-reset-password' : 'viewer-create-password'}>
          {reset ? 'New password' : 'Password'}
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
          {reset ? 'Confirm new password' : 'Confirm password'}
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
      return <p className="user-management-resource-state">Loading accounts...</p>;
    }
    if (users.status === 'error') {
      return (
        <div className="user-management-resource-state">
          <p role="alert">
            {userManagementErrorMessage(
              users.error,
              'The account list could not be loaded.',
            )}
          </p>
          <button
            type="button"
            disabled={controller.mutation !== null}
            onClick={() => void controller.refreshUsers().catch(() => undefined)}
          >
            Retry accounts
          </button>
        </div>
      );
    }
    if (users.data.length === 0) {
      return <p className="user-management-resource-state">No accounts found.</p>;
    }

    return (
      <div className="accounts-tab">
        <table className="user-management-table accounts-table">
          <thead>
            <tr>
              <th scope="col">User</th>
              <th scope="col">Role</th>
              <th scope="col">Status</th>
              <th scope="col">Last login</th>
              <th className="account-actions-column" scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.data.map((user) => (
              <tr key={user.id}>
                <td data-label="User">{user.username}</td>
                <td data-label="Role">
                  {user.role === 'administrator' ? 'Administrator' : 'Viewer'}
                </td>
                <td data-label="Status">{accountStatus(user)}</td>
                <td data-label="Last login">
                  {formatTimestamp(user.last_login_at_seconds)}
                </td>
                <td className="account-actions-cell" data-label="Actions">
                  {user.role === 'viewer' && (
                    <div className="account-actions">
                      <label className="switch-control">
                        <input
                          type="checkbox"
                          role="switch"
                          aria-label={`${user.enabled ? 'Disable' : 'Enable'} ${user.username}`}
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
                        label={`Reset password for ${user.username}`}
                        disabled={pending}
                        onClick={(event) => openAction({ kind: 'reset', user }, event.currentTarget)}
                      >
                        <KeyRound size={18} aria-hidden="true" />
                      </IconButton>
                      <IconButton
                        label={`Delete ${user.username}`}
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
          The account list could not be refreshed. Showing the last loaded accounts.
        </p>
      )}
      {renderResource()}

      {createOpen && (
        <UserManagementDialog
          title="Add viewer"
          description="Create a viewer account."
          pending={pending}
          returnFocusRef={createReturnFocusRef}
          onClose={closeCreate}
        >
          <form className="user-management-dialog-form" onSubmit={(event) => void submitCreate(event)} noValidate>
            <div className="field">
              <label htmlFor="viewer-create-username">Username</label>
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
                {submitting ? 'Creating viewer...' : 'Create viewer'}
              </button>
            </div>
          </form>
        </UserManagementDialog>
      )}

      {dialog?.kind === 'reset' && (
        <UserManagementDialog
          title="Reset viewer password"
          description={`Set a new password for ${dialog.user.username}. The viewer's active session may end immediately.`}
          pending={pending}
          returnFocusRef={actionReturnFocusRef}
          onClose={closeAction}
        >
          <form className="user-management-dialog-form" onSubmit={(event) => void submitReset(event)} noValidate>
            {credentialFields(true)}
            {dialogError !== null && <p className="form-error" role="alert">{dialogError}</p>}
            <div className="user-management-dialog-actions">
              <button className="primary-button" type="submit" disabled={pending}>
                {submitting ? 'Resetting password...' : 'Reset password'}
              </button>
            </div>
          </form>
        </UserManagementDialog>
      )}

      {dialog !== null && dialog.kind !== 'reset' && (
        <UserManagementDialog
          title={dialog.kind === 'delete'
            ? 'Delete viewer'
            : `${dialog.kind === 'enable' ? 'Enable' : 'Disable'} viewer`}
          description={dialog.kind === 'delete'
            ? `Delete ${dialog.user.username}? This action cannot be undone. The viewer's active session ends immediately.`
            : dialog.kind === 'disable'
              ? `Disable ${dialog.user.username}? The viewer's active session ends immediately.`
              : `Enable ${dialog.user.username}?`}
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
                ? `${dialog.kind === 'delete'
                  ? 'Deleting'
                  : dialog.kind === 'enable' ? 'Enabling' : 'Disabling'} viewer...`
                : `${dialog.kind === 'delete'
                  ? 'Delete'
                  : dialog.kind === 'enable' ? 'Enable' : 'Disable'} viewer`}
            </button>
          </div>
        </UserManagementDialog>
      )}
    </>
  );
}
