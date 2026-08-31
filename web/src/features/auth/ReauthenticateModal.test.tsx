import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ReauthenticateModal } from './ReauthenticateModal';

afterEach(cleanup);

describe('ReauthenticateModal', () => {
  it('submits the password and reports success', async () => {
    const reauthenticate = vi.fn().mockResolvedValue(undefined);
    const onSuccess = vi.fn();
    render(
      <ReauthenticateModal
        reauthenticate={reauthenticate}
        onSuccess={onSuccess}
        onCancel={() => undefined}
      />);

    await userEvent.type(screen.getByLabelText(/password/i), 'StrongPass9!');
    await userEvent.click(screen.getByRole('button', { name: /confirm/i }));

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(reauthenticate).toHaveBeenCalledWith('StrongPass9!');
  });

  it('shows a generic error and stays open when the password is wrong', async () => {
    const reauthenticate = vi
      .fn()
      .mockRejectedValue(new Error('E_AUTHENTICATION_FAILED'));
    const onSuccess = vi.fn();
    render(
      <ReauthenticateModal
        reauthenticate={reauthenticate}
        onSuccess={onSuccess}
        onCancel={() => undefined}
      />);

    await userEvent.type(screen.getByLabelText(/password/i), 'WrongPass9!');
    await userEvent.click(screen.getByRole('button', { name: /confirm/i }));

    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
  });
});
