import '@testing-library/jest-dom/vitest';

import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CameraApiClient } from '../../api/types';
import { SetupWizard } from './SetupWizard';

const makeClient = (): CameraApiClient => ({
  getJson: vi.fn(),
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

afterEach(cleanup);

async function advanceToReview(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
  await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
  await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
  await user.click(screen.getByRole('button', { name: /next/i }));

  await user.click(screen.getByRole('button', { name: /^next$/i }));

  await screen.findByRole('heading', { name: /review/i });
}

describe('SetupWizard', () => {
  it('walks credentials, IP, and review while preserving values moving forward and back', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    render(<SetupWizard client={client} peerIp="192.0.2.44" onInitialized={vi.fn()} />);

    expect(screen.getByRole('heading', { name: /create administrator/i })).toBeVisible();
    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /next/i }));

    await screen.findByRole('heading', { name: /management access/i });
    await user.type(screen.getByLabelText(/add a management address/i), '198.51.100.20');
    await user.click(screen.getByRole('button', { name: /add host/i }));
    expect(screen.getByText('198.51.100.20')).toBeVisible();

    await user.click(screen.getByRole('button', { name: /^back$/i }));
    await screen.findByRole('heading', { name: /create administrator/i });
    expect(screen.getByLabelText(/^username$/i)).toHaveValue('operator.one');
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('NorthStar!9');

    await user.click(screen.getByRole('button', { name: /next/i }));
    await screen.findByRole('heading', { name: /management access/i });
    expect(screen.getByText('198.51.100.20')).toBeVisible();

    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByRole('heading', { name: /review/i });
    expect(screen.getByText('operator.one')).toBeVisible();
    expect(screen.getByText('198.51.100.20')).toBeVisible();
    expect(screen.queryByText('NorthStar!9')).not.toBeInTheDocument();
  });

  it('submits exactly once, at review, with the username/password/peer_ip/management_ips body', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    const onInitialized = vi.fn();
    vi.mocked(client.postJson).mockResolvedValue({ required: false, runtime: 'running' });
    render(<SetupWizard client={client} peerIp="192.0.2.44" onInitialized={onInitialized} />);

    await advanceToReview(user);
    expect(client.postJson).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    await waitFor(() => expect(onInitialized).toHaveBeenCalledTimes(1));
    expect(client.postJson).toHaveBeenCalledTimes(1);
    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/setup/initialize',
      {
        username: 'operator.one',
        password: 'NorthStar!9',
        peer_ip: '192.0.2.44',
        // advanceToReview never adds a host: an empty list here proves the
        // key is always sent, not only when the operator adds something.
        management_ips: [],
      },
      expect.any(Function),
    );
  });

  it('submits the collected hosts as management_ips, and never the confirming peer itself', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockResolvedValue({ required: false, runtime: 'running' });
    render(<SetupWizard client={client} peerIp="192.0.2.44" onInitialized={vi.fn()} />);

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /next/i }));
    await user.type(screen.getByLabelText(/add a management address/i), '198.51.100.20');
    await user.click(screen.getByRole('button', { name: /add host/i }));
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByRole('heading', { name: /review/i });
    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    await waitFor(() => expect(client.postJson).toHaveBeenCalledTimes(1));
    expect(client.postJson).toHaveBeenCalledWith(
      '/api/v1/setup/initialize',
      expect.objectContaining({ peer_ip: '192.0.2.44', management_ips: ['198.51.100.20'] }),
      expect.any(Function),
    );
  });

  it('clears the password after a successful submission', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockResolvedValue({ required: false, runtime: 'running' });
    render(<SetupWizard client={client} peerIp="192.0.2.44" onInitialized={vi.fn()} />);

    await advanceToReview(user);
    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    await waitFor(() => expect(client.postJson).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole('button', { name: /^back$/i }));
    await user.click(screen.getByRole('button', { name: /^back$/i }));
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('');
    expect(screen.getByLabelText(/confirm password/i)).toHaveValue('');
  });

  it('keeps the review step disabled while an unresolved failure reconciliation settles', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockRejectedValue(new Error('offline'));
    render(
      <SetupWizard
        client={client}
        peerIp="192.0.2.44"
        onInitialized={vi.fn()}
        onInitializationFailed={() => new Promise(() => {})}
      />,
    );

    await advanceToReview(user);
    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /completing setup/i })).toBeDisabled();
      expect(screen.getByRole('button', { name: /^back$/i })).toBeDisabled();
    });
  });

  it('returns to the credentials step with the username and hosts intact when the server rejects submission', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockRejectedValue(new Error('reserved identity detail'));
    render(
      <SetupWizard
        client={client}
        peerIp="192.0.2.44"
        onInitialized={vi.fn()}
        onInitializationFailed={async () => false}
      />,
    );

    await user.type(screen.getByLabelText(/^username$/i), 'operator.one');
    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /next/i }));
    await user.type(screen.getByLabelText(/add a management address/i), '198.51.100.20');
    await user.click(screen.getByRole('button', { name: /add host/i }));
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByRole('heading', { name: /review/i });

    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    await screen.findByRole('heading', { name: /create administrator/i });
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Camera initialization failed. Check the credentials and try again.',
    );
    expect(screen.queryByText(/reserved identity detail/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/^username$/i)).toHaveValue('operator.one');
    // The password is cleared for security on a failed submission, so it
    // must be re-entered — that alone must not discard the collected host.
    expect(screen.getByLabelText(/^password$/i)).toHaveValue('');

    await user.type(screen.getByLabelText(/^password$/i), 'NorthStar!9');
    await user.type(screen.getByLabelText(/confirm password/i), 'NorthStar!9');
    await user.click(screen.getByRole('button', { name: /next/i }));
    await screen.findByRole('heading', { name: /management access/i });
    expect(screen.getByText('198.51.100.20')).toBeVisible();
  });

  it('does not show the failure banner when reconciliation reports the device already advanced', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockRejectedValue(new Error('offline'));
    const onInitializationFailed = vi.fn().mockResolvedValue(true);
    render(
      <SetupWizard
        client={client}
        peerIp="192.0.2.44"
        onInitialized={vi.fn()}
        onInitializationFailed={onInitializationFailed}
      />,
    );

    await advanceToReview(user);
    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    await waitFor(() => expect(onInitializationFailed).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('disables the submit control while the request is in flight', async () => {
    const user = userEvent.setup();
    const client = makeClient();
    vi.mocked(client.postJson).mockImplementation(() => new Promise<never>(() => {}));
    render(<SetupWizard client={client} peerIp="192.0.2.44" onInitialized={vi.fn()} />);

    await advanceToReview(user);
    await user.click(screen.getByRole('button', { name: /complete setup/i }));

    expect(screen.getByRole('button', { name: /completing setup/i })).toBeDisabled();
  });
});
