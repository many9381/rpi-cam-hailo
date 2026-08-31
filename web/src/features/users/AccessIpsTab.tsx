import {
  type FormEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react';
import { Pencil, Trash2 } from 'lucide-react';

import type { UserRole } from '../../api/types';
import { IconButton } from '../../components/IconButton';
import type { ManagementIp } from './contracts';
import { userManagementErrorMessage } from './publicError';
import { UserManagementDialog } from './UserManagementDialog';
import type {
  UserManagementCommandResult,
  UserManagementController,
} from './useUserManagement';

interface AccessIpsTabProps {
  controller: UserManagementController;
  createOpen: boolean;
  onCreateClose(): void;
}

type AccessIpDialog = {
  kind: 'edit' | 'delete';
  entry: ManagementIp;
};

const REFRESH_FAILURE_NOTICE =
  'Changes were applied, but the access IP list could not be refreshed.';

function formatTimestamp(seconds: number): string {
  return new Intl.DateTimeFormat().format(new Date(seconds * 1_000));
}

function roleLabel(role: UserRole): string {
  return role === 'administrator' ? 'Administrator' : 'Viewer';
}

export function AccessIpsTab({
  controller,
  createOpen,
  onCreateClose,
}: AccessIpsTabProps) {
  const [dialog, setDialog] = useState<AccessIpDialog | null>(null);
  const [createRole, setCreateRole] = useState<UserRole>('administrator');
  const [address, setAddress] = useState('');
  const [addressError, setAddressError] = useState<string | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const createReturnFocusRef = useRef<HTMLElement | null>(null);
  const actionReturnFocusRef = useRef<HTMLElement | null>(null);
  const activeSubmission = useRef<object | null>(null);
  const createWasOpen = useRef(false);
  const mounted = useRef(false);

  const resetFields = useCallback(() => {
    if (!mounted.current) {
      return;
    }
    setCreateRole('administrator');
    setAddress('');
    setAddressError(null);
    setDialogError(null);
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeSubmission.current = null;
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
      resetFields();
    } else if (!createOpen && wasOpen) {
      activeSubmission.current = null;
      resetFields();
      setSubmitting(false);
    }
    createWasOpen.current = createOpen;
  }, [createOpen, resetFields]);

  const pending = submitting || controller.mutation !== null;
  const { managementIps } = controller;
  const administratorCount = managementIps.data.management_ips.filter(
    (entry) => entry.role === 'administrator',
  ).length;

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

  const finishSuccess = (
    token: object,
    result: UserManagementCommandResult,
    close: () => void,
  ) => {
    if (!isCurrentSubmission(token)) {
      return;
    }
    activeSubmission.current = null;
    setSubmitting(false);
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
    resetFields();
    onCreateClose();
  };

  const closeAction = () => {
    if (pending) {
      return;
    }
    activeSubmission.current = null;
    resetFields();
    setDialog(null);
  };

  const validateAddress = (): boolean => {
    if (address.trim().length > 0) {
      setAddressError(null);
      return true;
    }
    setAddressError('Enter an address.');
    setDialogError(null);
    return false;
  };

  const submitCreate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!validateAddress()) {
      return;
    }
    const token = beginSubmission();
    if (token === null) {
      return;
    }
    try {
      const result = await controller.createManagementIp(createRole, address);
      finishSuccess(token, result, onCreateClose);
    } catch (error) {
      if (!isCurrentSubmission(token)) {
        return;
      }
      setDialogError(userManagementErrorMessage(
        error,
        'The access IP could not be added.',
      ));
      endSubmission(token);
    }
  };

  const submitEdit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (dialog?.kind !== 'edit' || !validateAddress()) {
      return;
    }
    const token = beginSubmission();
    if (token === null) {
      return;
    }
    const target = dialog.entry;
    try {
      const result = await controller.updateManagementIp(target, address);
      finishSuccess(token, result, () => setDialog(null));
    } catch (error) {
      if (!isCurrentSubmission(token)) {
        return;
      }
      setDialogError(userManagementErrorMessage(
        error,
        'The access IP could not be updated.',
      ));
      endSubmission(token);
    }
  };

  const submitDelete = async () => {
    if (dialog?.kind !== 'delete') {
      return;
    }
    const token = beginSubmission();
    if (token === null) {
      return;
    }
    const target = dialog.entry;
    try {
      const result = await controller.deleteManagementIp(target);
      finishSuccess(token, result, () => setDialog(null));
    } catch (error) {
      if (!isCurrentSubmission(token)) {
        return;
      }
      setDialogError(userManagementErrorMessage(
        error,
        'The access IP could not be deleted.',
      ));
      endSubmission(token);
    }
  };

  const openAction = (
    nextDialog: AccessIpDialog,
    opener: HTMLElement,
  ) => {
    if (pending) {
      return;
    }
    actionReturnFocusRef.current = opener;
    setAddress(nextDialog.entry.address);
    setAddressError(null);
    setDialogError(null);
    setNotice(null);
    setDialog(nextDialog);
  };

  const renderResource = () => {
    if (managementIps.status === 'loading' &&
        managementIps.data.management_ips.length === 0) {
      return <p className="user-management-resource-state">Loading access IPs...</p>;
    }
    if (managementIps.status === 'error') {
      return (
        <div className="user-management-resource-state">
          <p role="alert">
            {userManagementErrorMessage(
              managementIps.error,
              'The access IP list could not be loaded.',
            )}
          </p>
          <button
            type="button"
            disabled={pending}
            onClick={() => void controller.refreshManagementIps().catch(() => undefined)}
          >
            Retry access IPs
          </button>
        </div>
      );
    }
    if (managementIps.data.management_ips.length === 0) {
      return <p className="user-management-resource-state">No access IPs found.</p>;
    }

    return (
      <div className="access-ips-tab">
        <table className="user-management-table access-ips-table">
          <thead>
            <tr>
              <th scope="col">Role</th>
              <th scope="col">Address</th>
              <th scope="col">Protection state</th>
              <th scope="col">Creation time</th>
              <th className="access-ip-actions-column" scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {managementIps.data.management_ips.map((entry) => {
              const currentConnection = entry.role === 'administrator' &&
                entry.address === managementIps.data.current_peer_ip;
              const finalAdministrator = entry.role === 'administrator' &&
                administratorCount === 1;
              const protectedEntry = currentConnection || finalAdministrator;
              const protectedTitle = currentConnection
                ? 'The current administrator connection cannot be changed.'
                : finalAdministrator
                  ? 'The final administrator address cannot be changed.'
                  : null;

              return (
                <tr key={entry.id}>
                  <td data-label="Role">{roleLabel(entry.role)}</td>
                  <td data-label="Address">{entry.address}</td>
                  <td data-label="Protection state">
                    {currentConnection
                      ? 'Current connection'
                      : finalAdministrator
                        ? 'Final administrator address'
                        : 'Not protected'}
                  </td>
                  <td data-label="Creation time">
                    {formatTimestamp(entry.created_at_seconds)}
                  </td>
                  <td className="access-ip-actions-cell" data-label="Actions">
                    <div className="access-ip-actions">
                      <IconButton
                        label={`Edit ${entry.address}`}
                        title={protectedTitle ?? `Edit ${entry.address}`}
                        disabled={pending || protectedEntry}
                        onClick={(event) => openAction(
                          { kind: 'edit', entry },
                          event.currentTarget,
                        )}
                      >
                        <Pencil size={18} aria-hidden="true" />
                      </IconButton>
                      <IconButton
                        label={`Delete ${entry.address}`}
                        title={protectedTitle ?? `Delete ${entry.address}`}
                        disabled={pending || protectedEntry}
                        onClick={(event) => openAction(
                          { kind: 'delete', entry },
                          event.currentTarget,
                        )}
                      >
                        <Trash2 size={18} aria-hidden="true" />
                      </IconButton>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  };

  const addressField = (id: string) => (
    <div className="field">
      <label htmlFor={id}>Address</label>
      <input
        id={id}
        name="address"
        value={address}
        disabled={pending}
        aria-invalid={addressError === null ? undefined : true}
        aria-describedby={addressError === null ? undefined : `${id}-error`}
        onChange={(event) => setAddress(event.target.value)}
      />
      {addressError !== null && (
        <p id={`${id}-error`} className="form-error">{addressError}</p>
      )}
    </div>
  );

  return (
    <>
      {notice !== null && (
        <p className="user-management-resource-warning" role="status">{notice}</p>
      )}
      {managementIps.status === 'stale' && (
        <p className="user-management-resource-warning" role="alert">
          The access IP list could not be refreshed. Showing the last loaded access IPs.
        </p>
      )}
      {renderResource()}

      {createOpen && (
        <UserManagementDialog
          title="Add access IP"
          description="Add an administrator or viewer access address."
          pending={pending}
          returnFocusRef={createReturnFocusRef}
          onClose={closeCreate}
        >
          <form
            className="user-management-dialog-form"
            onSubmit={(event) => void submitCreate(event)}
            noValidate
          >
            <div className="field">
              <label htmlFor="access-ip-create-role">Role</label>
              <select
                id="access-ip-create-role"
                name="role"
                value={createRole}
                disabled={pending}
                onChange={(event) => setCreateRole(event.target.value as UserRole)}
              >
                <option value="administrator">Administrator</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
            {addressField('access-ip-create-address')}
            {dialogError !== null && <p className="form-error" role="alert">{dialogError}</p>}
            <div className="user-management-dialog-actions">
              <button className="primary-button" type="submit" disabled={pending}>
                {submitting ? 'Adding access IP...' : 'Add access IP'}
              </button>
            </div>
          </form>
        </UserManagementDialog>
      )}

      {dialog?.kind === 'edit' && (
        <UserManagementDialog
          title="Edit access IP"
          description={`Update the ${roleLabel(dialog.entry.role).toLowerCase()} access address.`}
          pending={pending}
          returnFocusRef={actionReturnFocusRef}
          onClose={closeAction}
        >
          <form
            className="user-management-dialog-form"
            onSubmit={(event) => void submitEdit(event)}
            noValidate
          >
            <div className="field">
              <span>Role</span>
              <strong>{roleLabel(dialog.entry.role)}</strong>
            </div>
            {addressField('access-ip-edit-address')}
            {dialogError !== null && <p className="form-error" role="alert">{dialogError}</p>}
            <div className="user-management-dialog-actions">
              <button className="primary-button" type="submit" disabled={pending}>
                {submitting ? 'Saving access IP...' : 'Save access IP'}
              </button>
            </div>
          </form>
        </UserManagementDialog>
      )}

      {dialog?.kind === 'delete' && (
        <UserManagementDialog
          title="Delete access IP"
          description={`Delete ${roleLabel(dialog.entry.role)} address ${dialog.entry.address}? This action cannot be undone.`}
          pending={pending}
          destructive
          returnFocusRef={actionReturnFocusRef}
          onClose={closeAction}
        >
          {dialogError !== null && <p className="form-error" role="alert">{dialogError}</p>}
          <div className="user-management-dialog-actions">
            <button
              className="danger-button"
              type="button"
              disabled={pending}
              onClick={() => void submitDelete()}
            >
              {submitting ? 'Deleting access IP...' : 'Delete access IP'}
            </button>
          </div>
        </UserManagementDialog>
      )}
    </>
  );
}
