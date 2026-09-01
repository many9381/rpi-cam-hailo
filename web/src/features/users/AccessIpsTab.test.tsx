import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '../../api/client';
import { LanguageProvider } from '../../i18n';
import type { ManagementIp } from './contracts';
import { makeUserManagementController } from './testSupport';
import { AccessIpsTab } from './AccessIpsTab';
import type { UserManagementController } from './useUserManagement';

const currentAdministrator: ManagementIp = {
  id: 1,
  address: '192.0.2.44',
  role: 'administrator',
  created_at_seconds: 1_700_000_000,
};

const otherAdministrator: ManagementIp = {
  id: 2,
  address: '198.51.100.8',
  role: 'administrator',
  created_at_seconds: 1_700_000_100,
};

const sharedViewer: ManagementIp = {
  id: 3,
  address: '192.0.2.44',
  role: 'viewer',
  created_at_seconds: 1_700_000_200,
};

const renderAccessIps = (
  managementIps = [currentAdministrator, otherAdministrator, sharedViewer],
  currentPeerIp = '192.0.2.44',
) => {
  const controller = makeUserManagementController({
    managementIps: {
      status: 'ready',
      data: { management_ips: managementIps, current_peer_ip: currentPeerIp },
      error: null,
    },
  });
  return {
    controller,
    view: render(
      <AccessIpsTab
        controller={controller}
        createOpen={false}
        onCreateClose={vi.fn()}
      />,
      { wrapper: LanguageProvider },
    ),
  };
};

function CreateAccessIpHarness({
  controller,
  onClosed = () => undefined,
}: {
  controller: UserManagementController;
  onClosed?: () => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <LanguageProvider>
      <button type="button" onClick={() => setOpen(true)}>Add access IP</button>
      <AccessIpsTab
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

async function openCreateAccessIp(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Add access IP' }));
  return screen.getByRole('dialog', { name: 'Add access IP' });
}

afterEach(cleanup);

describe('AccessIpsTab resource and protection states', () => {
  it('protects only the administrator row matching the current peer', () => {
    renderAccessIps();

    const rows = screen.getAllByRole('row').slice(1);
    const currentAdminRow = rows.find((row) =>
      within(row).queryByText('Administrator') !== null &&
      within(row).queryByText('192.0.2.44') !== null);
    const sharedViewerRow = rows.find((row) =>
      within(row).queryByText('Viewer') !== null &&
      within(row).queryByText('192.0.2.44') !== null);

    expect(currentAdminRow).toBeDefined();
    expect(sharedViewerRow).toBeDefined();
    expect(within(currentAdminRow!).getByText('Current connection')).toBeVisible();
    expect(within(currentAdminRow!).getByRole('button', { name: 'Edit 192.0.2.44' }))
      .toBeDisabled();
    expect(within(currentAdminRow!).getByRole('button', { name: 'Delete 192.0.2.44' }))
      .toBeDisabled();
    expect(within(currentAdminRow!).getByRole('button', { name: 'Edit 192.0.2.44' }))
      .toHaveAttribute(
        'title',
        'The current administrator connection cannot be changed.',
      );
    expect(within(sharedViewerRow!).getByRole('button', { name: 'Edit 192.0.2.44' }))
      .toBeEnabled();
    expect(within(sharedViewerRow!).getByRole('button', { name: 'Delete 192.0.2.44' }))
      .toBeEnabled();
  });

  it('protects the final administrator address even when it is not the current peer', () => {
    renderAccessIps([otherAdministrator, sharedViewer], '203.0.113.9');

    const administratorRow = screen.getByRole('row', { name: /administrator/i });
    expect(within(administratorRow).getByText('Final administrator address')).toBeVisible();
    expect(within(administratorRow).getByRole('button', { name: 'Edit 198.51.100.8' }))
      .toBeDisabled();
    expect(within(administratorRow).getByRole('button', { name: 'Delete 198.51.100.8' }))
      .toBeDisabled();
    expect(within(administratorRow).getByRole('button', { name: 'Delete 198.51.100.8' }))
      .toHaveAttribute(
        'title',
        'The final administrator address cannot be changed.',
      );
  });

  it('renders a semantic table with mobile labels and fixed icon actions', () => {
    renderAccessIps();

    const table = screen.getByRole('table');
    expect(within(table).getAllByRole('columnheader').map((header) => header.textContent))
      .toEqual(['Role', 'Address', 'Protection state', 'Creation time', 'Actions']);
    const row = screen.getByRole('row', { name: /198\.51\.100\.8/i });
    expect(within(row).getAllByRole('cell').map((cell) => cell.dataset.label))
      .toEqual(['Role', 'Address', 'Protection state', 'Creation time', 'Actions']);
    expect(within(row).getByText(
      new Intl.DateTimeFormat().format(new Date(otherAdministrator.created_at_seconds * 1_000)),
    )).toBeVisible();
    expect(within(row).getByRole('button', { name: 'Edit 198.51.100.8' }))
      .toHaveClass('icon-button');
    expect(within(row).getByRole('button', { name: 'Delete 198.51.100.8' }))
      .toHaveClass('icon-button');
  });

  it('renders loading and empty states independently', () => {
    const loadingController = makeUserManagementController({
      managementIps: {
        status: 'loading',
        data: { management_ips: [], current_peer_ip: '' },
        error: null,
      },
    });
    const view = render(
      <AccessIpsTab
        controller={loadingController}
        createOpen={false}
        onCreateClose={vi.fn()}
      />,
      { wrapper: LanguageProvider },
    );
    expect(screen.getByText('Loading access IPs...')).toBeVisible();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();

    const emptyController = makeUserManagementController();
    view.rerender(
      <AccessIpsTab
        controller={emptyController}
        createOpen={false}
        onCreateClose={vi.fn()}
      />,
    );
    expect(screen.getByText('No access IPs found.')).toBeVisible();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('renders a bounded initial error and retries only the IP resource', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      managementIps: {
        status: 'error',
        data: { management_ips: [], current_peer_ip: '' },
        error: new Error('private access detail'),
      },
    });
    render(
      <AccessIpsTab controller={controller} createOpen={false} onCreateClose={vi.fn()} />,
      { wrapper: LanguageProvider },
    );

    expect(screen.getByRole('alert')).toHaveTextContent(
      'The access IP list could not be loaded.',
    );
    expect(screen.queryByText('private access detail')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry access IPs' }));
    expect(controller.refreshManagementIps).toHaveBeenCalledTimes(1);
    expect(controller.refreshUsers).not.toHaveBeenCalled();
  });

  it('keeps stale rows visible with a bounded warning', () => {
    const controller = makeUserManagementController({
      managementIps: {
        status: 'stale',
        data: {
          management_ips: [currentAdministrator, otherAdministrator],
          current_peer_ip: currentAdministrator.address,
        },
        error: new Error('private stale detail'),
      },
    });
    render(
      <AccessIpsTab controller={controller} createOpen={false} onCreateClose={vi.fn()} />,
      { wrapper: LanguageProvider },
    );

    expect(screen.getByRole('alert')).toHaveTextContent(
      'The access IP list could not be refreshed. Showing the last loaded access IPs.',
    );
    expect(screen.queryByText('private stale detail')).not.toBeInTheDocument();
    expect(screen.getByRole('row', { name: /198\.51\.100\.8/i })).toBeVisible();
  });

  it('keeps the stale warning visible alongside an empty state', () => {
    const controller = makeUserManagementController({
      managementIps: {
        status: 'stale',
        data: { management_ips: [], current_peer_ip: '192.0.2.44' },
        error: new Error('private stale detail'),
      },
    });
    render(
      <AccessIpsTab controller={controller} createOpen={false} onCreateClose={vi.fn()} />,
      { wrapper: LanguageProvider },
    );

    expect(screen.getByRole('alert')).toHaveTextContent(
      'The access IP list could not be refreshed. Showing the last loaded access IPs.',
    );
    expect(screen.getByText('No access IPs found.')).toBeVisible();
    expect(screen.queryByText('private stale detail')).not.toBeInTheDocument();
  });
});

describe('AccessIpsTab role-scoped workflows', () => {
  it('adds one server-validated address for one of exactly two bounded roles', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController();
    render(<CreateAccessIpHarness controller={controller} />);
    const dialog = await openCreateAccessIp(user);

    const role = within(dialog).getByLabelText('Role');
    expect(role).toBeInstanceOf(HTMLSelectElement);
    expect(within(role).getAllByRole('option').map((option) => option.textContent))
      .toEqual(['Administrator', 'Viewer']);
    expect(within(dialog).getAllByRole('textbox')).toHaveLength(1);

    await user.selectOptions(role, 'viewer');
    await user.type(within(dialog).getByLabelText('Address'), '2001:db8::20');
    await user.click(within(dialog).getByRole('button', { name: 'Add access IP' }));

    expect(controller.createManagementIp).toHaveBeenCalledTimes(1);
    expect(controller.createManagementIp).toHaveBeenCalledWith('viewer', '2001:db8::20');
    expect(screen.queryByRole('dialog', { name: 'Add access IP' }))
      .not.toBeInTheDocument();
  });

  it('rejects only a blank address locally and leaves IP syntax to the server', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController();
    render(<CreateAccessIpHarness controller={controller} />);
    const dialog = await openCreateAccessIp(user);
    const address = within(dialog).getByLabelText('Address');

    await user.type(address, '   ');
    await user.click(within(dialog).getByRole('button', { name: 'Add access IP' }));
    expect(controller.createManagementIp).not.toHaveBeenCalled();
    expect(within(dialog).getByText('Enter an address.')).toBeVisible();

    await user.clear(address);
    await user.type(address, 'server-validates-this');
    await user.click(within(dialog).getByRole('button', { name: 'Add access IP' }));
    expect(controller.createManagementIp).toHaveBeenCalledWith(
      'administrator',
      'server-validates-this',
    );
  });

  it('edits only the address while keeping the entry role immutable', async () => {
    const user = userEvent.setup();
    const { controller } = renderAccessIps();
    const viewerRow = screen.getAllByRole('row').find((row) =>
      within(row).queryByText('Viewer') !== null);

    await user.click(within(viewerRow!).getByRole('button', { name: 'Edit 192.0.2.44' }));

    const dialog = screen.getByRole('dialog', { name: 'Edit access IP' });
    expect(within(dialog).getByText('Viewer')).toBeVisible();
    expect(within(dialog).queryByLabelText('Role')).not.toBeInTheDocument();
    const address = within(dialog).getByLabelText('Address');
    expect(address).toHaveValue('192.0.2.44');
    await user.clear(address);
    await user.type(address, '2001:db8::21');
    await user.click(within(dialog).getByRole('button', { name: 'Save access IP' }));

    expect(controller.updateManagementIp).toHaveBeenCalledTimes(1);
    expect(controller.updateManagementIp).toHaveBeenCalledWith(
      sharedViewer,
      '2001:db8::21',
    );
  });

  it('requires an alert dialog naming the role and normalized address before delete', async () => {
    const user = userEvent.setup();
    const { controller } = renderAccessIps();
    const viewerRow = screen.getAllByRole('row').find((row) =>
      within(row).queryByText('Viewer') !== null);

    await user.click(within(viewerRow!).getByRole('button', { name: 'Delete 192.0.2.44' }));

    const dialog = screen.getByRole('alertdialog', { name: 'Delete access IP' });
    expect(dialog).toHaveTextContent('Viewer');
    expect(dialog).toHaveTextContent('192.0.2.44');
    expect(controller.deleteManagementIp).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('button', { name: 'Delete access IP' }));
    expect(controller.deleteManagementIp).toHaveBeenCalledWith(sharedViewer);
  });

  it('keeps mutation failures in the dialog with allowlisted public copy', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      createManagementIp: vi.fn().mockRejectedValue(
        new ApiError(409, 'E_MANAGEMENT_IP_DUPLICATE'),
      ),
    });
    render(<CreateAccessIpHarness controller={controller} />);
    const dialog = await openCreateAccessIp(user);
    await user.type(within(dialog).getByLabelText('Address'), '192.0.2.44');

    await user.click(within(dialog).getByRole('button', { name: 'Add access IP' }));

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(
      'That address already exists for this role.',
    );
    expect(screen.getByRole('dialog', { name: 'Add access IP' })).toBeVisible();
  });

  it('clears a prior operation failure when the dialog closes and reopens', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      createManagementIp: vi.fn().mockRejectedValue(new Error('private detail')),
    });
    render(<CreateAccessIpHarness controller={controller} />);
    let dialog = await openCreateAccessIp(user);
    await user.type(within(dialog).getByLabelText('Address'), '192.0.2.44');
    await user.click(within(dialog).getByRole('button', { name: 'Add access IP' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(
      'The access IP could not be added.',
    );

    await user.click(within(dialog).getByRole('button', { name: 'Close Add access IP' }));
    dialog = await openCreateAccessIp(user);
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument();
    expect(within(dialog).getByLabelText('Address')).toHaveValue('');
  });

  it('closes after an applied mutation whose refresh failed and shows the exact notice', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      createManagementIp: vi.fn().mockResolvedValue({ refreshed: false }),
    });
    render(<CreateAccessIpHarness controller={controller} />);
    const dialog = await openCreateAccessIp(user);
    await user.type(within(dialog).getByLabelText('Address'), '2001:db8::20');

    await user.click(within(dialog).getByRole('button', { name: 'Add access IP' }));

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Changes were applied, but the access IP list could not be refreshed.',
    );
    expect(screen.queryByRole('dialog', { name: 'Add access IP' }))
      .not.toBeInTheDocument();
  });

  it('disables every IP action and create field during any active mutation', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({
      managementIps: {
        status: 'ready',
        data: {
          management_ips: [currentAdministrator, otherAdministrator, sharedViewer],
          current_peer_ip: currentAdministrator.address,
        },
        error: null,
      },
      mutation: 'delete_viewer',
    });
    render(<CreateAccessIpHarness controller={controller} />);
    const dialog = await openCreateAccessIp(user);

    for (const button of screen.getAllByRole('button', { name: /^Edit |^Delete / })) {
      expect(button).toBeDisabled();
    }
    expect(within(dialog).getByLabelText('Role')).toBeDisabled();
    expect(within(dialog).getByLabelText('Address')).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: 'Add access IP' })).toBeDisabled();
  });

  it('prevents duplicate create submissions while the first request is pending', async () => {
    const user = userEvent.setup();
    let settle!: (result: { refreshed: boolean }) => void;
    const controller = makeUserManagementController({
      createManagementIp: vi.fn(() =>
        new Promise<{ refreshed: boolean }>((resolve) => { settle = resolve; })),
    });
    render(<CreateAccessIpHarness controller={controller} />);
    const dialog = await openCreateAccessIp(user);
    await user.type(within(dialog).getByLabelText('Address'), '2001:db8::20');

    await user.dblClick(within(dialog).getByRole('button', { name: 'Add access IP' }));

    expect(controller.createManagementIp).toHaveBeenCalledTimes(1);
    expect(within(dialog).getByRole('button', { name: 'Adding access IP...' }))
      .toBeDisabled();
    await act(async () => settle({ refreshed: true }));
  });

  it('ignores a create completion after unmount', async () => {
    const user = userEvent.setup();
    let settle!: (result: { refreshed: boolean }) => void;
    const onClosed = vi.fn();
    const controller = makeUserManagementController({
      createManagementIp: vi.fn(() =>
        new Promise<{ refreshed: boolean }>((resolve) => { settle = resolve; })),
    });
    const view = render(
      <CreateAccessIpHarness controller={controller} onClosed={onClosed} />,
    );
    const dialog = await openCreateAccessIp(user);
    await user.type(within(dialog).getByLabelText('Address'), '2001:db8::20');
    await user.click(within(dialog).getByRole('button', { name: 'Add access IP' }));

    view.unmount();
    await act(async () => settle({ refreshed: true }));

    expect(onClosed).not.toHaveBeenCalled();
  });
});
