import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useRef, useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LanguageProvider } from '../../i18n';
import { UserManagementDialog } from './UserManagementDialog';

interface DialogHarnessProps {
  pending?: boolean;
  destructive?: boolean;
  onClosed?: () => void;
}

function DialogHarness({
  pending = false,
  destructive = false,
  onClosed = () => undefined,
}: DialogHarnessProps) {
  const [open, setOpen] = useState(true);
  const openerRef = useRef<HTMLButtonElement>(null);

  return (
    <LanguageProvider>
      <button ref={openerRef} type="button">Open user dialog</button>
      {open && (
        <UserManagementDialog
          title="Add viewer"
          description="Create a viewer account."
          pending={pending}
          destructive={destructive}
          returnFocusRef={openerRef}
          onClose={() => {
            onClosed();
            setOpen(false);
          }}
        >
          <input aria-label="Username" />
          <button type="button">Save viewer</button>
        </UserManagementDialog>
      )}
    </LanguageProvider>
  );
}

afterEach(cleanup);

describe('UserManagementDialog', () => {
  it('renders a labelled modal and focuses its close button', () => {
    render(<DialogHarness />);

    expect(screen.getByRole('dialog', { name: 'Add viewer' }))
      .toHaveAttribute('aria-modal', 'true');
    expect(screen.getByRole('button', { name: 'Close Add viewer' })).toHaveFocus();
  });

  it('uses alertdialog semantics for destructive confirmations', () => {
    render(<DialogHarness destructive />);

    const dialog = screen.getByRole('alertdialog', { name: 'Add viewer' });
    expect(dialog).toHaveAttribute('aria-describedby');
    expect(screen.getByText('Create a viewer account.')).toHaveAttribute(
      'id',
      dialog.getAttribute('aria-describedby'),
    );
  });

  it('wraps Tab forward from the last focusable child to the close button', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);

    screen.getByRole('button', { name: 'Save viewer' }).focus();
    await user.keyboard('{Tab}');

    expect(screen.getByRole('button', { name: 'Close Add viewer' })).toHaveFocus();
  });

  it('wraps Shift+Tab backward from the close button to the last focusable child', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);

    await user.keyboard('{Shift>}{Tab}{/Shift}');

    expect(screen.getByRole('button', { name: 'Save viewer' })).toHaveFocus();
  });

  it('closes on Escape when not pending', async () => {
    const user = userEvent.setup();
    const onClosed = vi.fn();
    render(<DialogHarness onClosed={onClosed} />);

    await user.keyboard('{Escape}');

    expect(onClosed).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('closes from its backdrop when not pending', async () => {
    const user = userEvent.setup();
    const onClosed = vi.fn();
    const { container } = render(<DialogHarness onClosed={onClosed} />);

    await user.click(container.querySelector('.user-management-dialog-backdrop')!);

    expect(onClosed).toHaveBeenCalledTimes(1);
  });

  it('rejects close requests and keeps focus contained while pending', async () => {
    const user = userEvent.setup();
    const onClosed = vi.fn();
    const { container } = render(<DialogHarness pending onClosed={onClosed} />);
    const dialog = screen.getByRole('dialog', { name: 'Add viewer' });

    await user.keyboard('{Escape}');
    expect(dialog).toHaveFocus();

    await user.click(container.querySelector('.user-management-dialog-backdrop')!);
    expect(dialog).toHaveFocus();

    await user.click(screen.getByRole('button', { name: 'Close Add viewer' }));
    expect(dialog).toHaveFocus();

    expect(onClosed).not.toHaveBeenCalled();
    expect(dialog).toBeInTheDocument();
  });

  it('keeps focus on its container while pending', async () => {
    const user = userEvent.setup();
    render(<DialogHarness pending />);

    const dialog = screen.getByRole('dialog', { name: 'Add viewer' });
    expect(dialog).toHaveAttribute('tabindex', '-1');
    expect(dialog).toHaveFocus();
    await user.keyboard('{Tab}');
    expect(dialog).toHaveFocus();
    await user.keyboard('{Shift>}{Tab}{/Shift}');
    expect(dialog).toHaveFocus();
  });

  it('restores focus to a still-mounted opener after closing', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);

    await user.click(screen.getByRole('button', { name: 'Close Add viewer' }));

    expect(screen.getByRole('button', { name: 'Open user dialog' })).toHaveFocus();
  });
});
