import '@testing-library/jest-dom/vitest';

import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient } from '../api/types';
import { SetupPage } from './SetupPage';

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

afterEach(cleanup);

describe('SetupPage', () => {
  it('shows the immutable peer address and sends it unchanged', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockResolvedValue({ required: false, runtime: 'running' });
    render(
      <SetupPage client={client} peerIp="2001:0db8:0000::0010" onInitialized={vi.fn()} />,
    );

    const panel = screen.getByRole('region', { name: 'Create administrator' });
    expect(panel).toHaveClass('auth-panel');
    expect(panel.closest('main')).toHaveClass('auth-surface');
    expect(panel.querySelector('.brand-mark')).toHaveTextContent('CF');
    expect(panel.querySelectorAll('.field')).toHaveLength(4);
    expect(screen.getByRole('button', { name: /initialize camera/i }))
      .toHaveClass('primary-button');
    expect(screen.getByLabelText(/management peer address/i)).toHaveValue('2001:0db8:0000::0010');
    expect(screen.getByLabelText(/management peer address/i)).toHaveAttribute('readonly');
    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /initialize camera/i }));

    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/setup/initialize',
      { username: 'operator.one', password: 'NorthStar!9', peer_ip: '2001:0db8:0000::0010' },
      expect.any(Function),
    );
  });

  it('renders field feedback and does not submit invalid credentials', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    render(<SetupPage client={client} peerIp="192.0.2.10" onInitialized={vi.fn()} />);

    await user.type(screen.getByLabelText(/^username$/i), 'user');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'Different!9');
    await user.click(screen.getByRole('button', { name: /initialize camera/i }));

    expect(screen.getByText('Username must be 5 to 32 characters.')).toBeVisible();
    expect(screen.getByText('Passwords do not match.')).toBeVisible();
    expect(screen.getByText('Username must be 5 to 32 characters.'))
      .toHaveClass('form-error');
    expect(screen.getByText('Passwords do not match.')).toHaveClass('form-error');
    expect(client.postJson).not.toHaveBeenCalled();
  });

  it('shows the authoritative nine-character minimum in policy feedback', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    render(<SetupPage client={client} peerIp="192.0.2.10" onInitialized={vi.fn()} />);

    expect(screen.getByLabelText(/^password$/i)).toHaveAttribute('minlength', '9');
    expect(screen.getByLabelText(/^password$/i)).toHaveAttribute('maxlength', '128');
    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'Short!9A');
    await user.type(screen.getByLabelText(/confirm password/i), 'Short!9A');
    await user.click(screen.getByRole('button', { name: /initialize camera/i }));

    expect(screen.getByText('Password must be 9 to 128 characters.')).toBeVisible();
    expect(client.postJson).not.toHaveBeenCalled();
  });

  it('uses masked password controls and generic server failure feedback', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockRejectedValue(new Error('reserved identity detail'));
    render(<SetupPage client={client} peerIp="192.0.2.10" onInitialized={vi.fn()} />);

    expect(screen.getByLabelText(/^password$/i)).toHaveAttribute('type', 'password');
    expect(screen.getByLabelText(/confirm password/i)).toHaveAttribute('type', 'password');
    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /initialize camera/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Camera initialization failed. Check the credentials and try again.',
    );
    expect(screen.getByRole('alert')).toHaveClass('form-error');
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('');
    expect(screen.getByLabelText(/confirm password/i)).toHaveValue('');
    expect(screen.queryByText(/reserved identity detail/i)).not.toBeInTheDocument();
  });

  it('does not report setup success for a deferred runtime response', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    const onInitialized = vi.fn();
    vi.mocked(client.postJson).mockImplementation(async (_path, _body, parser) =>
      parser({ required: false, runtime: 'deferred' }));
    render(
      <SetupPage
        client={client}
        peerIp="192.0.2.10"
        onInitialized={onInitialized}
      />,
    );

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /initialize camera/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Camera initialization failed. Check the credentials and try again.',
    );
    expect(onInitialized).not.toHaveBeenCalled();
  });

  it('clears both passwords on success before requesting a status recheck', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    const onInitialized = vi.fn();
    vi.mocked(client.postJson).mockResolvedValue({ required: false, runtime: 'running' });
    render(<SetupPage client={client} peerIp="192.0.2.10" onInitialized={onInitialized} />);

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /initialize camera/i }));

    await waitFor(() => expect(onInitialized).toHaveBeenCalledTimes(1));
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('');
    expect(screen.getByLabelText(/confirm password/i)).toHaveValue('');
    expect(onInitialized.mock.invocationCallOrder[0])
      .toBeGreaterThan(vi.mocked(client.postJson).mock.invocationCallOrder[0]);
  });

  it('clears both passwords before an unresolved failure reconciliation settles', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockRejectedValue(new Error('offline'));
    render(<SetupPage client={client} peerIp="192.0.2.10"
      onInitialized={vi.fn()}
      onInitializationFailed={() => new Promise(() => {})} />);

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /initialize camera/i }));

    await waitFor(() => {
      expect(screen.getByLabelText(/^password$/i)).toHaveValue('');
      expect(screen.getByLabelText(/confirm password/i)).toHaveValue('');
    });
  });
});
