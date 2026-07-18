import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it } from 'vitest';

import { makeUserManagementController } from '../features/users/testSupport';
import { UsersPage } from './UsersPage';

afterEach(cleanup);

describe('UsersPage tab composition', () => {
  it('renders the exact heading, tabs, active panel, and active command', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController();
    render(<UsersPage controller={controller} />);

    expect(screen.getByRole('heading', { level: 1, name: 'Users & access' }))
      .toBeVisible();
    const tablist = screen.getByRole('tablist');
    const tabs = within(tablist).getAllByRole('tab');
    expect(tabs.map((tab) => tab.textContent)).toEqual(['Accounts', 'Access IPs']);

    const accountsTab = screen.getByRole('tab', { name: 'Accounts' });
    const accessIpsTab = screen.getByRole('tab', { name: 'Access IPs' });
    expect(accountsTab).toHaveAttribute('id', 'users-accounts-tab');
    expect(accountsTab).toHaveAttribute('aria-controls', 'users-accounts-panel');
    expect(accountsTab).toHaveAttribute('aria-selected', 'true');
    expect(accountsTab).toHaveAttribute('tabindex', '0');
    expect(accessIpsTab).toHaveAttribute('id', 'users-access-ips-tab');
    expect(accessIpsTab).toHaveAttribute('aria-controls', 'users-access-ips-panel');
    expect(accessIpsTab).toHaveAttribute('aria-selected', 'false');
    expect(accessIpsTab).toHaveAttribute('tabindex', '-1');

    const accountsPanel = screen.getByRole('tabpanel');
    expect(accountsPanel).toHaveAttribute('id', 'users-accounts-panel');
    expect(accountsPanel).toHaveAttribute('aria-labelledby', 'users-accounts-tab');
    expect(screen.getByText('No accounts found.')).toBeVisible();
    expect(screen.queryByText('No access IPs found.')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add viewer' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Add access IP' }))
      .not.toBeInTheDocument();

    await user.click(accessIpsTab);

    expect(accessIpsTab).toHaveAttribute('aria-selected', 'true');
    expect(accountsTab).toHaveAttribute('aria-selected', 'false');
    const accessIpsPanel = screen.getByRole('tabpanel');
    expect(accessIpsPanel).toHaveAttribute('id', 'users-access-ips-panel');
    expect(accessIpsPanel).toHaveAttribute('aria-labelledby', 'users-access-ips-tab');
    expect(screen.getByText('No access IPs found.')).toBeVisible();
    expect(screen.queryByText('No accounts found.')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add access IP' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Add viewer' }))
      .not.toBeInTheDocument();
  });

  it('switches tabs and moves focus with arrows, Home, and End', async () => {
    const user = userEvent.setup();
    render(<UsersPage controller={makeUserManagementController()} />);
    const accountsTab = screen.getByRole('tab', { name: 'Accounts' });
    const accessIpsTab = screen.getByRole('tab', { name: 'Access IPs' });

    accountsTab.focus();
    await user.keyboard('{ArrowRight}');
    expect(accessIpsTab).toHaveFocus();
    expect(accessIpsTab).toHaveAttribute('aria-selected', 'true');

    await user.keyboard('{ArrowRight}');
    expect(accountsTab).toHaveFocus();
    expect(accountsTab).toHaveAttribute('aria-selected', 'true');

    await user.keyboard('{ArrowLeft}');
    expect(accessIpsTab).toHaveFocus();
    expect(accessIpsTab).toHaveAttribute('aria-selected', 'true');

    await user.keyboard('{Home}');
    expect(accountsTab).toHaveFocus();
    expect(accountsTab).toHaveAttribute('aria-selected', 'true');

    await user.keyboard('{End}');
    expect(accessIpsTab).toHaveFocus();
    expect(accessIpsTab).toHaveAttribute('aria-selected', 'true');
  });

  it('passes controlled create state only to the active child and resets it', async () => {
    const user = userEvent.setup();
    render(<UsersPage controller={makeUserManagementController()} />);

    await user.click(screen.getByRole('button', { name: 'Add viewer' }));
    expect(screen.getByRole('dialog', { name: 'Add viewer' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Close Add viewer' }));
    expect(screen.queryByRole('dialog', { name: 'Add viewer' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Add viewer' }));
    await user.click(screen.getByRole('tab', { name: 'Access IPs' }));
    expect(screen.queryByRole('dialog', { name: 'Add viewer' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Accounts' }));
    expect(screen.queryByRole('dialog', { name: 'Add viewer' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Access IPs' }));
    await user.click(screen.getByRole('button', { name: 'Add access IP' }));
    expect(screen.getByRole('dialog', { name: 'Add access IP' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Close Add access IP' }));
    expect(screen.queryByRole('dialog', { name: 'Add access IP' }))
      .not.toBeInTheDocument();
  });

  it('disables the active create command during any mutation', async () => {
    const user = userEvent.setup();
    const controller = makeUserManagementController({ mutation: 'reset_viewer_password' });
    render(<UsersPage controller={controller} />);

    expect(screen.getByRole('button', { name: 'Add viewer' })).toBeDisabled();
    await user.click(screen.getByRole('tab', { name: 'Access IPs' }));
    expect(screen.getByRole('button', { name: 'Add access IP' })).toBeDisabled();
  });
});
