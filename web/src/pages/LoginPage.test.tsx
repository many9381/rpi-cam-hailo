import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { LanguageProvider } from '../i18n';
import { LoginPage } from './LoginPage';

afterEach(cleanup);

describe('LoginPage', () => {
  it('submits credentials through auth and clears the masked password on success', async () => {
    const user = userEvent.setup();
    const login = vi.fn().mockResolvedValue(undefined);
    render(<LanguageProvider><LoginPage login={login} /></LanguageProvider>);

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
    render(<LanguageProvider><LoginPage login={login} /></LanguageProvider>);

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

  it('shows the initial credential panel when the server supplies one', async () => {
    render(<LanguageProvider><LoginPage login={vi.fn()} initialCredential={{
      username: 'setup.x7k2q', password: 'T4m#pR9vLw' }} /></LanguageProvider>);

    expect(await screen.findByText('setup.x7k2q')).toBeInTheDocument();
    expect(screen.getByText('T4m#pR9vLw')).toBeInTheDocument();
  });

  it('shows no credential panel when the server supplies none', () => {
    render(<LanguageProvider><LoginPage login={vi.fn()} initialCredential={null} /></LanguageProvider>);

    expect(screen.queryByText(/초기 설정|initial setup/i)).not.toBeInTheDocument();
  });
});
