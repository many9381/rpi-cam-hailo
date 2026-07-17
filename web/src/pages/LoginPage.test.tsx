import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LoginPage } from './LoginPage';

afterEach(cleanup);

describe('LoginPage', () => {
  it('submits credentials through auth and clears the masked password on success', async () => {
    const user = userEvent.setup();
    const login = vi.fn().mockResolvedValue(undefined);
    render(<LoginPage login={login} />);

    expect(screen.getByRole('heading', { name: /camera login/i })).toBeVisible();
    const password = screen.getByLabelText(/^password$/i);
    expect(password).toHaveAttribute('type', 'password');
    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(password, 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(login).toHaveBeenCalledWith('operator.one', 'NorthStar!9');
    expect(password).toHaveValue('');
  });

  it('shows only generic failure feedback and clears the submitted password', async () => {
    const user = userEvent.setup();
    const login = vi.fn().mockRejectedValue(new Error('private identity detail'));
    render(<LoginPage login={login} />);

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    const password = screen.getByLabelText(/^password$/i);
    await user.type(password, 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Sign in failed. Check your credentials and try again.',
    );
    expect(screen.queryByText(/private identity detail/i)).not.toBeInTheDocument();
    expect(password).toHaveValue('');
  });
});
