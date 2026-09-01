import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HashRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Principal } from '../api/types';
import { LanguageProvider } from '../i18n';
import '../styles.css';
import { ViewerShell } from './ViewerShell';

const principal: Principal = { username: 'viewer.one', role: 'viewer' };

function renderShell() {
  return render(
    <LanguageProvider>
      <HashRouter>
        <ViewerShell principal={principal} logout={vi.fn()} changePassword={vi.fn()}>
          Monitor content
        </ViewerShell>
      </HashRouter>
    </LanguageProvider>,
  );
}

afterEach(() => {
  cleanup();
  window.location.hash = '';
  document.body.classList.remove('drawer-active');
});

describe('ViewerShell', () => {
  it('offers exactly the Live monitoring navigation and common account menu', () => {
    renderShell();

    const navigation = screen.getByRole('navigation', { name: /primary/i });
    expect(within(navigation).getAllByRole('link')).toHaveLength(1);
    expect(within(navigation).getByRole('link', { name: 'Live' }))
      .toHaveAttribute('href', '#/monitor');
    expect(screen.getByRole('button', { name: 'Open user menu' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Refresh device state' })).not.toBeInTheDocument();
    for (const label of ['Dashboard', 'Cameras', 'AI', 'System', 'Users', 'Operational']) {
      expect(screen.queryByText(label, { exact: true })).not.toBeInTheDocument();
    }
    expect(screen.getByText('Monitor content')).toBeVisible();
  });

  it('keeps modal drawer Escape and focus restoration behavior', async () => {
    const user = userEvent.setup();
    renderShell();
    const trigger = screen.getByRole('button', { name: 'Open navigation' });

    await user.click(trigger);
    expect(screen.getByRole('dialog', { name: 'Navigation' })).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByRole('button', { name: 'Close navigation' })).toHaveFocus();
    expect(document.body).toHaveClass('drawer-active');
    await user.click(screen.getByRole('button', { name: 'Close navigation' }));
    expect(document.body).not.toHaveClass('drawer-active');
    expect(trigger).toHaveFocus();

    await user.click(trigger);
    expect(document.body).toHaveClass('drawer-active');
    await user.keyboard('{Escape}');

    expect(screen.queryByRole('dialog', { name: 'Navigation' })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(document.body).not.toHaveClass('drawer-active');
  });

  it('traps focus in the drawer and restores it after backdrop dismissal', async () => {
    const user = userEvent.setup();
    renderShell();
    const trigger = screen.getByRole('button', { name: 'Open navigation' });

    await user.click(trigger);
    await user.tab({ shift: true });
    expect(within(screen.getByRole('dialog')).getByRole('link', { name: 'Live' })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Close navigation' })).toHaveFocus();

    await user.click(screen.getByRole('button', { name: 'Dismiss navigation' }));
    expect(screen.queryByRole('dialog', { name: 'Navigation' })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(document.body).not.toHaveClass('drawer-active');
  });

  it('removes the drawer body class when unmounted while open', async () => {
    const user = userEvent.setup();
    const view = renderShell();

    await user.click(screen.getByRole('button', { name: 'Open navigation' }));
    expect(document.body).toHaveClass('drawer-active');
    view.unmount();
    expect(document.body).not.toHaveClass('drawer-active');
  });
});
