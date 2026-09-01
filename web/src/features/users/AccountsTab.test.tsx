import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useRef, useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '../../api/client';
import { LanguageProvider } from '../../i18n';
import type { ManagedUser } from './contracts';
import { makeUserManagementController } from './testSupport';
import { AccountsTab } from './AccountsTab';
import type { UserManagementController } from './useUserManagement';

const administrator: ManagedUser = {
  id: 1,
  username: 'admin.user',
  role: 'administrator',
  enabled: false,
  lock_until_seconds: 100,
  created_at_seconds: 10,
  password_changed_at_seconds: 20,
  last_login_at_seconds: null,
};

const viewer: ManagedUser = {
  id: 2,
  username: 'viewer.one',
  role: 'viewer',
  enabled: true,
  lock_until_seconds: 1_700_000_000,
  created_at_seconds: 30,
  password_changed_at_seconds: 40,
  last_login_at_seconds: 1_710_000_000,
};

const formatTimestamp = (seconds: number) =>
  new Intl.DateTimeFormat().format(new Date(seconds * 1_000));

const renderAccounts = (
  controller = makeUserManagementController({
    users: { status: 'ready', data: [administrator, viewer], error: null },
  }),
) => render(
  <AccountsTab controller={controller} createOpen={false} onCreateClose={vi.fn()} />,
  { wrapper: LanguageProvider },
);

function CreateViewerHarness({
  controller,
  onClosed = () => undefined,
}: {
  controller: UserManagementController;
  onClosed?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const openerRef = useRef<HTMLButtonElement>(null);

  return (
    <LanguageProvider>
      <button ref={openerRef} type="button" onClick={() => setOpen(true)}>
        Add viewer
      </button>
      <AccountsTab
        controller={controller}
        createOpen={open}
        onCreateClose={() => {
          onClosed();
          setOpen(false);
        }}
      />
    </LanguageProvider>
  );
}

async function openCreateViewer(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Add viewer' }));
  return screen.getByRole('dialog', { name: 'Add viewer' });
}

async function fillCreateViewer(
  user: ReturnType<typeof userEvent.setup>,
  username = 'viewer.two',
  password = 'ViewerPass9!',
  confirmation = password,
) {
  await user.type(screen.getByLabelText('Username'), username);
  await user.type(screen.getByLabelText('Password'), password);
  await user.type(screen.getByLabelText('Confirm password'), confirmation);
}

async function fillResetPassword(
  user: ReturnType<typeof userEvent.setup>,
  password = 'ViewerPass10!',
  confirmation = password,
) {
  await user.type(screen.getByLabelText('New password'), password);
  await user.type(screen.getByLabelText('Confirm new password'), confirmation);
}

afterEach(cleanup);

describe('AccountsTab resource and account rows', () => {
  it('renders semantic account rows with mobile labels and role-scoped actions', () => {
    renderAccounts();

    const table = screen.getByRole('table');
    expect(within(table).getAllByRole('columnheader').map((header) => header.textContent))
      .toEqual(['User', 'Role', 'Status', 'Last login', 'Actions']);

    const adminRow = screen.getByRole('row', { name: /admin\.user/i });
    const viewerRow = screen.getByRole('row', { name: /viewer\.one/i });
    expect(within(adminRow).getAllByRole('cell').map((cell) => cell.dataset.label))
      .toEqual(['User', 'Role', 'Status', 'Last login', 'Actions']);
    expect(within(viewerRow).getAllByRole('cell').map((cell) => cell.dataset.label))
      .toEqual(['User', 'Role', 'Status', 'Last login', 'Actions']);

    expect(within(adminRow).getByText('Administrator')).toBeVisible();
    expect(within(adminRow).getByText('Disabled')).toBeVisible();
    expect(within(adminRow).getByText('Never')).toBeVisible();
    expect(within(adminRow).queryByRole('switch')).not.toBeInTheDocument();
    expect(within(adminRow).queryByRole('button', { name: /disable|reset|delete/i }))
      .not.toBeInTheDocument();

    expect(within(viewerRow).getByText('Viewer')).toBeVisible();
    expect(within(viewerRow).getByText(
      `Locked until ${formatTimestamp(viewer.lock_until_seconds!)}`,
    )).toBeVisible();
    expect(within(viewerRow).getByText(formatTimestamp(viewer.last_login_at_seconds!)))
      .toBeVisible();
    const viewerSwitch = within(viewerRow).getByRole('switch', {
      name: 'Disable viewer.one',
    });
    expect(viewerSwitch).toBeChecked();
    expect(viewerSwitch.nextElementSibling).toBeInstanceOf(HTMLSpanElement);
    expect(viewerSwitch.nextElementSibling).toHaveAttribute('aria-hidden', 'true');
    expect(viewerSwitch.nextElementSibling).toBeVisible();
    expect(within(viewerRow).getByRole('button', {
      name: 'Reset password for viewer.one',
    })).toHaveAttribute('title', 'Reset password for viewer.one');
    expect(within(viewerRow).getByRole('button', { name: 'Delete viewer.one' }))
      .toHaveAttribute('title', 'Delete viewer.one');
  });

  it('renders the loading state independently', () => {
    renderAccounts(makeUserManagementController({
      users: { status: 'loading', data: [], error: null },
    }));

    expect(screen.getByText('Loading accounts...')).toBeVisible();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('renders the empty state independently', () => {
    renderAccounts(makeUserManagementController());

    expect(screen.getByText('No accounts found.')).toBeVisible();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('renders an initial error with a retry command', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      users: { status: 'error', data: [], error: new Error('private detail') },
    });
    renderAccounts(controller);

    expect(screen.getByRole('alert')).toHaveTextContent(
      'The account list could not be loaded.',
    );
    expect(screen.queryByText('private detail')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry accounts' }));
    expect(controller.refreshUsers).toHaveBeenCalledTimes(1);
  });

  it('keeps stale rows visible with an independent warning', () => {
    renderAccounts(makeUserManagementController({
      users: {
        status: 'stale',
        data: [viewer],
        error: new Error('private stale detail'),
      },
    }));

    expect(screen.getByRole('alert')).toHaveTextContent(
      'The account list could not be refreshed. Showing the last loaded accounts.',
    );
    expect(screen.queryByText('private stale detail')).not.toBeInTheDocument();
    expect(screen.getByRole('row', { name: /viewer\.one/i })).toBeVisible();
  });

  it('renders the stale warning independently when no accounts are cached', () => {
    renderAccounts(makeUserManagementController({
      users: {
        status: 'stale',
        data: [],
        error: new Error('private stale detail'),
      },
    }));

    expect(screen.getByRole('alert')).toHaveTextContent(
      'The account list could not be refreshed. Showing the last loaded accounts.',
    );
    expect(screen.getByText('No accounts found.')).toBeVisible();
    expect(screen.queryByText('private stale detail')).not.toBeInTheDocument();
  });
});

describe('AccountsTab viewer workflows', () => {
  it('rejects weak and mismatched create credentials locally and clears secrets', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController();
    render(<CreateViewerHarness controller={controller} />);
    await openCreateViewer(user);
    await fillCreateViewer(user, 'viewer.two', 'Short!9A', 'Different!9');

    await user.click(screen.getByRole('button', { name: 'Create viewer' }));

    expect(controller.createViewer).not.toHaveBeenCalled();
    expect(screen.getByText('Password must be 9 to 128 characters.')).toBeVisible();
    expect(screen.getByText('Passwords do not match.')).toBeVisible();
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(screen.getByLabelText('Confirm password')).toHaveValue('');
  });

  it('submits only the exact username and password once, then closes and restores focus', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController();
    const onClosed = vi.fn();
    render(<CreateViewerHarness controller={controller} onClosed={onClosed} />);
    const opener = screen.getByRole('button', { name: 'Add viewer' });
    await openCreateViewer(user);
    await fillCreateViewer(user);

    await user.dblClick(screen.getByRole('button', { name: 'Create viewer' }));

    await waitFor(() => expect(onClosed).toHaveBeenCalledTimes(1));
    expect(controller.createViewer).toHaveBeenCalledTimes(1);
    expect(controller.createViewer).toHaveBeenCalledWith('viewer.two', 'ViewerPass9!');
    expect(screen.queryByRole('dialog', { name: 'Add viewer' })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it('clears create secrets before a deferred controller request settles', async () => {
    const user = userEvent.setup();
    let settle!: (result: { refreshed: boolean }) => void;
    const controller = makeUserManagementController({
      createViewer: vi.fn((_username: string, _password: string) =>
        new Promise<{ refreshed: boolean }>((resolve) => { settle = resolve; })),
    });
    render(<CreateViewerHarness controller={controller} />);
    await openCreateViewer(user);
    await fillCreateViewer(user);

    await user.click(screen.getByRole('button', { name: 'Create viewer' }));

    expect(controller.createViewer).toHaveBeenCalledWith('viewer.two', 'ViewerPass9!');
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(screen.getByLabelText('Confirm password')).toHaveValue('');
    await act(async () => settle({ refreshed: true }));
  });

  it('keeps create open with bounded public failure copy and cleared secrets', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      createViewer: vi.fn().mockRejectedValue(new Error('ViewerPass9! private detail')),
    });
    render(<CreateViewerHarness controller={controller} />);
    await openCreateViewer(user);
    await fillCreateViewer(user);

    await user.click(screen.getByRole('button', { name: 'Create viewer' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The viewer could not be created.',
    );
    expect(screen.getByRole('dialog', { name: 'Add viewer' })).toBeVisible();
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(screen.getByLabelText('Confirm password')).toHaveValue('');
    expect(screen.queryByText(/ViewerPass9!|private detail/)).not.toBeInTheDocument();
  });

  it('closes create after a successful mutation whose refresh failed and shows a notice', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      createViewer: vi.fn().mockResolvedValue({ refreshed: false }),
    });
    render(<CreateViewerHarness controller={controller} />);
    await openCreateViewer(user);
    await fillCreateViewer(user);

    await user.click(screen.getByRole('button', { name: 'Create viewer' }));

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Changes were applied, but the account list could not be refreshed.',
    );
    expect(screen.queryByRole('dialog', { name: 'Add viewer' })).not.toBeInTheDocument();
  });

  it.each([
    [true, 'Disable viewer.one', 'Disable viewer', false],
    [false, 'Enable viewer.one', 'Enable viewer', true],
  ] as const)(
    'requires confirmation before changing enabled=%s through %s',
    async (enabled, switchName, confirmationName, requestedEnabled) => {
      const user = userEvent.setup();
      const target = { ...viewer, enabled, lock_until_seconds: null };
      const controller = makeUserManagementController({
        users: { status: 'ready', data: [target], error: null },
      });
      renderAccounts(controller);

      await user.click(screen.getByRole('switch', { name: switchName }));

      const dialog = screen.getByRole('dialog', { name: confirmationName });
      expect(dialog).toHaveTextContent('viewer.one');
      if (enabled) {
        expect(dialog).toHaveTextContent(/active session ends/i);
      }
      expect(controller.setViewerEnabled).not.toHaveBeenCalled();
      await user.click(within(dialog).getByRole('button', { name: confirmationName }));
      expect(controller.setViewerEnabled).toHaveBeenCalledWith(2, requestedEnabled);
    },
  );

  it('keeps a failed disable confirmation open with its exact safe fallback', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      users: { status: 'ready', data: [viewer], error: null },
      setViewerEnabled: vi.fn().mockRejectedValue(new Error('private enable detail')),
    });
    renderAccounts(controller);
    await user.click(screen.getByRole('switch', { name: 'Disable viewer.one' }));

    await user.click(screen.getByRole('button', { name: 'Disable viewer' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The viewer could not be disabled.',
    );
    expect(screen.getByRole('dialog', { name: 'Disable viewer' })).toBeVisible();
    expect(screen.queryByText('private enable detail')).not.toBeInTheDocument();
  });

  it('validates reset against the target username and clears both fields after failure', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      users: { status: 'ready', data: [viewer], error: null },
      resetViewerPassword: vi.fn().mockRejectedValue(
        new ApiError(409, 'E_PASSWORD_REUSE'),
      ),
    });
    renderAccounts(controller);
    await user.click(screen.getByRole('button', {
      name: 'Reset password for viewer.one',
    }));
    const resetDialog = screen.getByRole('dialog', { name: 'Reset viewer password' });
    expect(within(resetDialog).getByText(
      "Set a new password for viewer.one. The viewer's active session may end immediately.",
    )).toBeVisible();
    await fillResetPassword(user, 'viewer.one', 'viewer.one');
    await user.click(screen.getByRole('button', { name: 'Reset password' }));
    expect(controller.resetViewerPassword).not.toHaveBeenCalled();
    expect(screen.getByText('Password must differ from the username.')).toBeVisible();
    expect(screen.getByLabelText('New password')).toHaveValue('');
    expect(screen.getByLabelText('Confirm new password')).toHaveValue('');

    await fillResetPassword(user);
    await user.click(screen.getByRole('button', { name: 'Reset password' }));

    expect(controller.resetViewerPassword).toHaveBeenCalledWith(2, 'ViewerPass10!');
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The current or previous password cannot be reused.',
    );
    expect(screen.getByRole('dialog', { name: 'Reset viewer password' })).toBeVisible();
    expect(screen.getByLabelText('New password')).toHaveValue('');
    expect(screen.getByLabelText('Confirm new password')).toHaveValue('');
  });

  it('clears reset secrets before a deferred controller request settles', async () => {
    const user = userEvent.setup();
    let settle!: (result: { refreshed: boolean }) => void;
    const controller = makeUserManagementController({
      users: { status: 'ready', data: [viewer], error: null },
      resetViewerPassword: vi.fn((_id: number, _password: string) =>
        new Promise<{ refreshed: boolean }>((resolve) => { settle = resolve; })),
    });
    renderAccounts(controller);
    await user.click(screen.getByRole('button', {
      name: 'Reset password for viewer.one',
    }));
    await fillResetPassword(user);

    await user.click(screen.getByRole('button', { name: 'Reset password' }));

    expect(controller.resetViewerPassword).toHaveBeenCalledWith(2, 'ViewerPass10!');
    expect(screen.getByLabelText('New password')).toHaveValue('');
    expect(screen.getByLabelText('Confirm new password')).toHaveValue('');
    await act(async () => settle({ refreshed: true }));
  });

  it('requires destructive confirmation naming the viewer before deletion', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      users: { status: 'ready', data: [viewer], error: null },
    });
    renderAccounts(controller);

    await user.click(screen.getByRole('button', { name: 'Delete viewer.one' }));

    const dialog = screen.getByRole('alertdialog', { name: 'Delete viewer' });
    expect(within(dialog).getByText(
      "Delete viewer.one? This action cannot be undone. The viewer's active session ends immediately.",
    )).toBeVisible();
    expect(controller.deleteViewer).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('button', { name: 'Delete viewer' }));
    expect(controller.deleteViewer).toHaveBeenCalledWith(2);
  });

  it('uses the exact enable, reset, and delete fallback strings', async () => {
    const user = userEvent.setup();
    const disabledViewer = { ...viewer, enabled: false, lock_until_seconds: null };
    const controller = makeUserManagementController({
      users: { status: 'ready', data: [disabledViewer], error: null },
      setViewerEnabled: vi.fn().mockRejectedValue(new Error('private')),
      resetViewerPassword: vi.fn().mockRejectedValue(new Error('private')),
      deleteViewer: vi.fn().mockRejectedValue(new Error('private')),
    });
    const view = render(
      <AccountsTab controller={controller} createOpen={false} onCreateClose={vi.fn()} />,
      { wrapper: LanguageProvider },
    );

    await user.click(screen.getByRole('switch', { name: 'Enable viewer.one' }));
    await user.click(screen.getByRole('button', { name: 'Enable viewer' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The viewer could not be enabled.',
    );

    view.rerender(
      <AccountsTab controller={controller} createOpen={false} onCreateClose={vi.fn()} />,
    );
    await user.click(screen.getByRole('button', { name: 'Close Enable viewer' }));
    await user.click(screen.getByRole('button', {
      name: 'Reset password for viewer.one',
    }));
    await fillResetPassword(user);
    await user.click(screen.getByRole('button', { name: 'Reset password' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The viewer password could not be reset.',
    );
    await user.click(screen.getByRole('button', { name: 'Close Reset viewer password' }));

    await user.click(screen.getByRole('button', { name: 'Delete viewer.one' }));
    await user.click(screen.getByRole('button', { name: 'Delete viewer' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The viewer could not be deleted.',
    );
  });

  it('disables every viewer control while any controller mutation is active', () => {
    const controller = makeUserManagementController({
      users: { status: 'ready', data: [viewer], error: null },
      mutation: 'create_management_ip',
    });
    renderAccounts(controller);

    expect(screen.getByRole('switch', { name: 'Disable viewer.one' })).toBeDisabled();
    expect(screen.getByRole('button', {
      name: 'Reset password for viewer.one',
    })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Delete viewer.one' })).toBeDisabled();
  });

  it('ignores a create completion after unmount and clears its controlled lifetime', async () => {
    const user = userEvent.setup();
    let settle!: (result: { refreshed: boolean }) => void;
    const onClosed = vi.fn();
    const controller = makeUserManagementController({
      createViewer: vi.fn((_username: string, _password: string) =>
        new Promise<{ refreshed: boolean }>((resolve) => { settle = resolve; })),
    });
    const view = render(
      <CreateViewerHarness controller={controller} onClosed={onClosed} />,
    );
    await openCreateViewer(user);
    await fillCreateViewer(user);
    await user.click(screen.getByRole('button', { name: 'Create viewer' }));

    view.unmount();
    await act(async () => settle({ refreshed: true }));

    expect(onClosed).not.toHaveBeenCalled();
  });
});
