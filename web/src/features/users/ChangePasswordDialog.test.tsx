import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { StrictMode, useLayoutEffect, useRef, useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError } from '../../api/client';
import { ChangePasswordDialog } from './ChangePasswordDialog';

interface DialogHarnessProps {
  changePassword(
    currentPassword: string,
    replacementPassword: string,
    signal?: AbortSignal,
  ): Promise<void>;
  onClosed?: () => void;
}

function DialogHarness({ changePassword, onClosed = () => undefined }: DialogHarnessProps) {
  const [open, setOpen] = useState(true);
  const openerRef = useRef<HTMLButtonElement>(null);

  return (
    <>
      <button ref={openerRef} type="button">Open password dialog</button>
      <ChangePasswordDialog
        open={open}
        returnFocusRef={openerRef}
        changePassword={changePassword}
        onClose={() => {
          onClosed();
          setOpen(false);
        }}
      />
    </>
  );
}

async function fillPasswords(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Current password'), 'CurrentPass9!');
  await user.type(screen.getByLabelText('New password'), 'ReplacementPass9!');
  await user.type(screen.getByLabelText('Confirm new password'), 'ReplacementPass9!');
}

function expectPasswordsCleared() {
  expect(screen.getByLabelText('Current password')).toHaveValue('');
  expect(screen.getByLabelText('New password')).toHaveValue('');
  expect(screen.getByLabelText('Confirm new password')).toHaveValue('');
}

afterEach(cleanup);

describe('ChangePasswordDialog', () => {
  it('renders labelled native password inputs and focuses the current password', () => {
    const openerRef = { current: document.createElement('button') };
    const changePassword = vi.fn();
    render(
      <ChangePasswordDialog open returnFocusRef={openerRef} changePassword={changePassword}
        onClose={() => undefined} />,
    );

    const dialog = screen.getByRole('dialog', { name: 'Change password' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByLabelText('Current password')).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText('Current password')).toHaveAttribute('autocomplete', 'current-password');
    expect(screen.getByLabelText('New password')).toHaveAttribute('autocomplete', 'new-password');
    expect(screen.getByLabelText('Confirm new password')).toHaveAttribute('autocomplete', 'new-password');
    expect(screen.getByLabelText('Current password')).toHaveFocus();
  });

  it('rejects a mismatched confirmation without submitting secrets', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn();
    render(<DialogHarness changePassword={changePassword} />);

    await user.type(screen.getByLabelText('Current password'), 'CurrentPass9!');
    await user.type(screen.getByLabelText('New password'), 'ReplacementPass9!');
    await user.type(screen.getByLabelText('Confirm new password'), 'DifferentPass9!');
    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(changePassword).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent('New passwords do not match.');
    expectPasswordsCleared();
  });

  it('clears partial values before displaying a required-password error', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn();
    render(<DialogHarness changePassword={changePassword} />);

    await user.type(screen.getByLabelText('New password'), 'ReplacementPass9!');
    await user.type(screen.getByLabelText('Confirm new password'), 'ReplacementPass9!');
    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(changePassword).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent('Enter the current password.');
    expectPasswordsCleared();
  });

  it('submits exact values once and disables conflicting controls while pending', async () => {
    const user = userEvent.setup();
    let settle!: () => void;
    const changePassword = vi.fn(() => new Promise<void>((resolve) => { settle = resolve; }));
    render(<DialogHarness changePassword={changePassword} />);
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(changePassword).toHaveBeenCalledWith(
      'CurrentPass9!',
      'ReplacementPass9!',
      expect.any(AbortSignal),
    );
    expect(screen.getByRole('button', { name: 'Changing password...' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Close change password dialog' })).toBeDisabled();
    expect(screen.getByLabelText('Current password')).toBeDisabled();
    settle();
  });

  it('clears every password after a successful submission without logging or storing it', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();
    const consoleLog = vi.spyOn(console, 'log');
    const consoleError = vi.spyOn(console, 'error');
    const storageGet = vi.spyOn(Storage.prototype, 'getItem');
    const storageSet = vi.spyOn(Storage.prototype, 'setItem');
    const openerRef = { current: document.createElement('button') };
    try {
      render(
        <ChangePasswordDialog open returnFocusRef={openerRef} changePassword={changePassword}
          onClose={onClose} />,
      );
      await fillPasswords(user);

      await user.click(screen.getByRole('button', { name: 'Change password' }));

      await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
      expectPasswordsCleared();
      expect(consoleLog).not.toHaveBeenCalled();
      expect(consoleError).not.toHaveBeenCalled();
      expect(storageGet).not.toHaveBeenCalled();
      expect(storageSet).not.toHaveBeenCalled();
    } finally {
      consoleLog.mockRestore();
      consoleError.mockRestore();
      storageGet.mockRestore();
      storageSet.mockRestore();
    }
  });

  it('clears every password after failure and renders an allowlisted public error code', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn().mockRejectedValue(
      new ApiError(400, 'E_CURRENT_PASSWORD'),
    );
    render(<DialogHarness changePassword={changePassword} />);
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('E_CURRENT_PASSWORD');
    expectPasswordsCleared();
  });

  it.each([
    ['an unknown private code', 'E_PRIVATE_DIAGNOSTIC'],
    ['an oversized code', `E_${'X'.repeat(256)}`],
  ])('does not render %s from an API failure', async (_case, code) => {
    const user = userEvent.setup();
    const changePassword = vi.fn().mockRejectedValue(new ApiError(400, code));
    render(<DialogHarness changePassword={changePassword} />);
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to change password.');
    expect(screen.getByRole('alert')).not.toHaveTextContent(code);
  });

  it('settles success in StrictMode after its effect lifecycle replay', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const openerRef = { current: document.createElement('button') };
    render(
      <StrictMode>
        <ChangePasswordDialog open returnFocusRef={openerRef}
          changePassword={async () => undefined} onClose={onClose} />
      </StrictMode>,
    );
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));

    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });

  it('renders an allowed failure in StrictMode after its effect lifecycle replay', async () => {
    const user = userEvent.setup();
    const openerRef = { current: document.createElement('button') };
    render(
      <StrictMode>
        <ChangePasswordDialog open returnFocusRef={openerRef}
          changePassword={async () => Promise.reject(new ApiError(400, 'E_PASSWORD_REUSE'))}
          onClose={() => undefined} />
      </StrictMode>,
    );
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('E_PASSWORD_REUSE');
  });

  it('clears every password before notifying its parent that it should close', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn();
    const onClose = vi.fn();
    const openerRef = { current: document.createElement('button') };
    render(
      <ChangePasswordDialog open returnFocusRef={openerRef} changePassword={changePassword}
        onClose={onClose} />,
    );
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Close change password dialog' }));

    expect(onClose).toHaveBeenCalledTimes(1);
    expectPasswordsCleared();
  });

  it('clears passwords, closes on Escape, and returns focus to its opener', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn();
    const onClosed = vi.fn();
    render(<DialogHarness changePassword={changePassword} onClosed={onClosed} />);
    await fillPasswords(user);

    await user.keyboard('{Escape}');

    expect(onClosed).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open password dialog' })).toHaveFocus();
  });

  it('ignores a request completion after its parent closes the dialog', async () => {
    const user = userEvent.setup();
    let settle!: () => void;
    let requestSignal: AbortSignal | undefined;
    const changePassword = vi.fn((_current: string, _replacement: string, signal?: AbortSignal) => {
      requestSignal = signal;
      return new Promise<void>((resolve) => { settle = resolve; });
    });
    const onClose = vi.fn();
    const openerRef = { current: document.createElement('button') };
    const view = render(
      <ChangePasswordDialog open returnFocusRef={openerRef} changePassword={changePassword}
        onClose={onClose} />,
    );
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));
    view.rerender(
      <ChangePasswordDialog open={false} returnFocusRef={openerRef}
        changePassword={changePassword} onClose={onClose} />,
    );
    settle();
    await Promise.resolve();

    expect(requestSignal?.aborted).toBe(true);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('ignores an immediate request completion during parent close before passive cleanup', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    let requestSignal: AbortSignal | undefined;
    function ImmediateCloseHarness() {
      const [open, setOpen] = useState(true);
      const settle = useRef<(() => void) | null>(null);
      const openerRef = useRef<HTMLButtonElement>(null);
      useLayoutEffect(() => {
        if (!open) {
          settle.current?.();
        }
      }, [open]);

      return (
        <>
          <button type="button" onClick={() => setOpen(false)}>Parent close</button>
          <ChangePasswordDialog
            open={open}
            returnFocusRef={openerRef}
            changePassword={(_current, _replacement, signal) => {
              requestSignal = signal;
              return new Promise<void>((resolve) => { settle.current = resolve; });
            }}
            onClose={onClose}
          />
        </>
      );
    }
    render(<ImmediateCloseHarness />);
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));
    await user.click(screen.getByRole('button', { name: 'Parent close' }));

    expect(requestSignal?.aborted).toBe(true);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('cycles Tab from the last control to the close control and Shift+Tab back', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn();
    render(<DialogHarness changePassword={changePassword} />);

    await user.click(screen.getByRole('button', { name: 'Change password' }));
    await user.keyboard('{Tab}');
    expect(screen.getByRole('button', { name: 'Close change password dialog' })).toHaveFocus();

    await user.keyboard('{Shift>}{Tab}{/Shift}');
    expect(screen.getByRole('button', { name: 'Change password' })).toHaveFocus();
  });

  it('keeps focus on the dialog container while all controls are pending-disabled', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn(() => new Promise<void>(() => undefined));
    render(<DialogHarness changePassword={changePassword} />);
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));

    const dialog = screen.getByRole('dialog', { name: 'Change password' });
    expect(dialog).toHaveAttribute('tabindex', '-1');
    expect(dialog).toHaveFocus();
    await user.keyboard('{Tab}');
    expect(dialog).toHaveFocus();
    await user.keyboard('{Shift>}{Tab}{/Shift}');
    expect(dialog).toHaveFocus();
  });

  it('clears a failure error when the controlled dialog closes and reopens', async () => {
    const user = userEvent.setup();
    const changePassword = vi.fn().mockRejectedValue(new ApiError(400, 'E_PASSWORD_REUSE'));
    const openerRef = { current: document.createElement('button') };
    const view = render(
      <ChangePasswordDialog open returnFocusRef={openerRef} changePassword={changePassword}
        onClose={() => undefined} />,
    );
    await fillPasswords(user);
    await user.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('E_PASSWORD_REUSE');

    view.rerender(
      <ChangePasswordDialog open={false} returnFocusRef={openerRef}
        changePassword={changePassword} onClose={() => undefined} />,
    );
    view.rerender(
      <ChangePasswordDialog open returnFocusRef={openerRef} changePassword={changePassword}
        onClose={() => undefined} />,
    );

    expect(screen.getByRole('alert')).toBeEmptyDOMElement();
  });

  it('aborts its active request when unmounted', async () => {
    const user = userEvent.setup();
    let requestSignal: AbortSignal | undefined;
    const changePassword = vi.fn((_current: string, _replacement: string, signal?: AbortSignal) =>
      new Promise<void>((_resolve, reject) => {
        requestSignal = signal;
        signal?.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'));
        }, { once: true });
      }));
    const view = render(<DialogHarness changePassword={changePassword} />);
    await fillPasswords(user);

    await user.click(screen.getByRole('button', { name: 'Change password' }));
    view.unmount();

    expect(requestSignal?.aborted).toBe(true);
  });
});
