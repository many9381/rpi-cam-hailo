import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HashRouter } from 'react-router-dom';

import type { Principal } from '../api/types';
import type { AuditStatusController } from '../features/audit/useAuditStatus';
import {
  makeSettings,
  makeSettingsController,
  makeSettingsSnapshot,
} from '../features/settings/testSupport';
import type { RuntimeSettingsController } from '../features/settings/useRuntimeSettings';
import { AppShell } from './AppShell';

const principal: Principal = { username: 'operator.one', role: 'administrator' };

const renderShell = (
  logout = vi.fn(),
  runtimeSettings?: RuntimeSettingsController,
  changePassword = vi.fn(),
  auditStatus?: AuditStatusController,
) => render(
  <HashRouter>
    <AppShell principal={principal} logout={logout}
      changePassword={changePassword} runtimeSettings={runtimeSettings}
      auditStatus={auditStatus}>Dashboard content</AppShell>
  </HashRouter>,
);

const warningAuditStatus: AuditStatusController = {
  state: 'ready',
  data: {
    current_events: 91,
    max_events: 100,
    usage_percent: 91,
    warning: true,
    rotated_event_count: 2,
    last_rotation_at_seconds: 1_784_333_000,
    last_rotated_sequence: 2,
  },
  refresh: vi.fn(async () => undefined),
};

afterEach(() => {
  cleanup();
  window.location.hash = '';
});

describe('AppShell', () => {
  it('renders the A-layout navigation and accessible fixed-size icon controls', async () => {
    renderShell();

    const navigation = screen.getByRole('navigation', { name: /primary/i });
    expect(within(navigation).getAllByRole('link').map((link) => link.textContent))
      .toEqual(['Dashboard', 'Cameras', 'AI', 'System', 'Users']);
    for (const name of ['Open navigation', 'Refresh device state', 'Open user menu']) {
      const button = screen.getByRole('button', { name });
      expect(button).toHaveAttribute('title', name);
      expect(button).toHaveClass('icon-button');
    }
    expect(screen.getByText('Dashboard content')).toBeVisible();
    expect(screen.getByText('Operational')).toBeVisible();
  });

  it('places one audit capacity warning before route content without changing navigation', () => {
    renderShell(vi.fn(), undefined, vi.fn(), warningAuditStatus);

    const warning = screen.getByRole('alert');
    expect(warning.nextSibling?.textContent).toContain('Dashboard content');
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(screen.getByRole('link', { name: 'Review audit records' }))
      .toHaveAttribute('href', '#/system#audit-records');
    expect(within(screen.getByRole('navigation', { name: /primary/i }))
      .getAllByRole('link').map((link) => link.textContent))
      .toEqual(['Dashboard', 'Cameras', 'AI', 'System', 'Users']);
  });

  it('opens a modal mobile drawer and closes it on Escape with focus restored', async () => {
    const user = userEvent.setup();
    renderShell();
    const trigger = screen.getByRole('button', { name: 'Open navigation' });

    await user.click(trigger);
    const drawer = screen.getByRole('dialog', { name: /navigation/i });
    expect(drawer).toHaveAttribute('aria-modal', 'true');
    expect(within(drawer).getAllByRole('link').map((link) => link.textContent))
      .toEqual(['Dashboard', 'Cameras', 'AI', 'System', 'Users']);
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
    expect(document.getElementById('user-disclosure')).not.toHaveAttribute('role', 'menu');
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeVisible();

    await user.keyboard('{Escape}');

    expect(document.getElementById('user-disclosure')).not.toBeInTheDocument();
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(trigger).toHaveFocus();
  });

  it('shows a compact pending notice linked to the changed settings domain', () => {
    const cameraPending = makeSettings('imx708-720p50', 5_000);
    const controller = makeSettingsController({
      snapshot: makeSettingsSnapshot({ pending: cameraPending }),
      draft: cameraPending,
    });
    const { rerender } = renderShell(vi.fn(), controller);

    expect(screen.getByRole('status')).toHaveTextContent(
      'Runtime settings are waiting to be applied.',
    );
    expect(screen.getByRole('link', { name: 'Review camera settings' }))
      .toHaveAttribute('href', '#/cameras');

    const aiPending = makeSettings();
    aiPending.models[0] = { ...aiPending.models[0], confidence_threshold: 0.6 };
    const aiController = makeSettingsController({
      snapshot: makeSettingsSnapshot({ pending: aiPending }),
      draft: aiPending,
    });
    rerender(
      <HashRouter>
        <AppShell principal={principal} logout={vi.fn()}
          changePassword={vi.fn()} runtimeSettings={aiController}>Dashboard content</AppShell>
      </HashRouter>,
    );
    expect(screen.getByRole('link', { name: 'Review AI settings' }))
      .toHaveAttribute('href', '#/ai');
  });

  it('shows bounded recovery and restored-runtime notices', () => {
    const recovery = makeSettingsSnapshot({ state: 'recovery_required' });
    const { rerender } = renderShell(vi.fn(), makeSettingsController({
      snapshot: recovery, draft: recovery.active,
    }));
    expect(screen.getByRole('status')).toHaveTextContent(
      'Runtime settings need recovery.',
    );

    const failed = makeSettingsSnapshot({
      pending: makeSettings('imx708-720p50', 5_000),
      lastApply: { status: 'failed', code: 'E_SETTINGS_APPLY_FAILED', restored: true },
    });
    rerender(
      <HashRouter>
        <AppShell principal={principal} logout={vi.fn()}
          changePassword={vi.fn()} runtimeSettings={makeSettingsController({
            status: 'error', snapshot: failed, draft: failed.pending,
          })}>Dashboard content</AppShell>
      </HashRouter>,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Apply failed. The previous camera runtime was restored.',
    );
    expect(screen.queryByText('E_SETTINGS_APPLY_FAILED')).not.toBeInTheDocument();
  });
});
