import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HashRouter } from 'react-router-dom';

import type { Principal } from '../api/types';
import { AppShell } from './AppShell';

const principal: Principal = { username: 'operator.one', role: 'administrator' };

const renderShell = (logout = vi.fn()) => render(
  <HashRouter>
    <AppShell principal={principal} logout={logout}>Dashboard content</AppShell>
  </HashRouter>,
);

afterEach(() => {
  cleanup();
  window.location.hash = '';
});

describe('AppShell', () => {
  it('renders the A-layout navigation and accessible fixed-size icon controls', async () => {
    renderShell();

    const navigation = screen.getByRole('navigation', { name: /primary/i });
    for (const name of ['Dashboard', 'Cameras', 'AI', 'System']) {
      expect(within(navigation).getByRole('link', { name })).toBeVisible();
    }
    for (const name of ['Open navigation', 'Refresh device state', 'Open user menu']) {
      const button = screen.getByRole('button', { name });
      expect(button).toHaveAttribute('title', name);
      expect(button).toHaveClass('icon-button');
    }
    expect(screen.getByText('Dashboard content')).toBeVisible();
    expect(screen.getByText('Operational')).toBeVisible();
  });

  it('opens a modal mobile drawer and closes it on Escape with focus restored', async () => {
    const user = userEvent.setup();
    renderShell();
    const trigger = screen.getByRole('button', { name: 'Open navigation' });

    await user.click(trigger);
    const drawer = screen.getByRole('dialog', { name: /navigation/i });
    expect(drawer).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByRole('button', { name: 'Close navigation' })).toHaveFocus();
    await user.keyboard('{Escape}');

    expect(screen.queryByRole('dialog', { name: /navigation/i })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it('closes the drawer after route selection and restores focus', async () => {
    const user = userEvent.setup();
    renderShell();
    const trigger = screen.getByRole('button', { name: 'Open navigation' });
    await user.click(trigger);

    await user.click(within(screen.getByRole('dialog')).getByRole('link', { name: 'Cameras' }));

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(window.location.hash).toBe('#/cameras');
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('shows the server principal in a user menu and invokes logout', async () => {
    const user = userEvent.setup();
    const logout = vi.fn().mockResolvedValue(undefined);
    renderShell(logout);

    await user.click(screen.getByRole('button', { name: 'Open user menu' }));
    expect(screen.getByText('operator.one')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Sign out' }));

    expect(logout).toHaveBeenCalledTimes(1);
  });

  it('treats the user control as a disclosure and restores focus on Escape', async () => {
    const user = userEvent.setup();
    renderShell();
    const trigger = screen.getByRole('button', { name: 'Open user menu' });

    await user.click(trigger);

    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(trigger).toHaveAttribute('aria-controls', 'user-disclosure');
    expect(screen.getByTestId('user-disclosure')).not.toHaveAttribute('role', 'menu');
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();

    await user.keyboard('{Escape}');

    expect(screen.queryByTestId('user-disclosure')).not.toBeInTheDocument();
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(trigger).toHaveFocus();
  });
});
