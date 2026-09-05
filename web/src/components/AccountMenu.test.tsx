import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Principal } from '../api/types';
import { LanguageProvider } from '../i18n';
import { AccountMenu } from './AccountMenu';

const principal: Principal = { username: 'viewer.one', role: 'viewer' };

afterEach(cleanup);

describe('AccountMenu', () => {
  it('renders the principal and signs out from its disclosure', async () => {
    const user = userEvent.setup();
    const logout = vi.fn().mockResolvedValue(undefined);
    render(
      <LanguageProvider>
        <AccountMenu principal={principal} logout={logout} changePassword={vi.fn()} />
      </LanguageProvider>,
    );

    expect(screen.getByText('viewer.one')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Open user menu' }));

    expect(screen.getByText('viewer')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Change password' }))
      .toHaveClass('user-menu-change-password');
    expect(screen.getByRole('button', { name: 'Sign out' })).toHaveClass('user-menu-sign-out');
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(logout).toHaveBeenCalledOnce();
  });

  it('restores focus from the password dialog to its mounted opener before closing the disclosure', async () => {
    const user = userEvent.setup();
    render(
      <LanguageProvider>
        <AccountMenu principal={principal} logout={vi.fn()} changePassword={vi.fn()} />
      </LanguageProvider>,
    );
    const trigger = screen.getByRole('button', { name: 'Open user menu' });

    await user.click(trigger);
    expect(trigger).toHaveAttribute('aria-controls', 'user-disclosure');
    expect(document.getElementById('user-disclosure')).not.toHaveAttribute('role', 'menu');
    await user.keyboard('{Escape}');
    expect(document.getElementById('user-disclosure')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();

    await user.click(trigger);
    const changePassword = screen.getByRole('button', { name: 'Change password' });
    await user.click(changePassword);
    expect(screen.getByRole('dialog', { name: 'Change password' })).toBeVisible();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Change password' })).not.toBeInTheDocument();
    expect(changePassword).toHaveFocus();

    await user.keyboard('{Escape}');
    expect(document.getElementById('user-disclosure')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});
