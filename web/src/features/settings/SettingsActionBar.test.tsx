import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it } from 'vitest';

import { LanguageProvider } from '../../i18n';
import { SettingsActionBar } from './SettingsActionBar';
import {
  makeSettings,
  makeSettingsController,
  makeSettingsSnapshot,
} from './testSupport';

afterEach(cleanup);

describe('SettingsActionBar', () => {
  it('enables Save only for a valid dirty full draft', () => {
    const snapshot = makeSettingsSnapshot();
    const valid = makeSettingsController({
      snapshot,
      draft: makeSettings('imx708-720p50', 5_000),
      dirty: true,
    });
    const { rerender } = render(<SettingsActionBar controller={valid} />, {
      wrapper: LanguageProvider,
    });
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeEnabled();

    rerender(<SettingsActionBar controller={{ ...valid, dirty: false }} />);
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();

    rerender(<SettingsActionBar controller={{
      ...valid,
      draft: { ...valid.draft!, camera: {
        ...valid.draft!.camera, bitrate_kbps: 20_001,
      } },
    }} />);
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
  });

  it('allows an unchanged recovery draft to replace invalid stored state', async () => {
    const user = userEvent.setup();
    const snapshot = makeSettingsSnapshot({ state: 'recovery_required' });
    const controller = makeSettingsController({
      snapshot,
      draft: snapshot.active,
      dirty: false,
    });
    render(<SettingsActionBar controller={controller} />, { wrapper: LanguageProvider });

    const save = screen.getByRole('button', { name: 'Save changes' });
    expect(save).toBeEnabled();
    await user.click(save);
    expect(controller.save).toHaveBeenCalledOnce();
  });

  it('saves the draft and discards only a clean durable pending snapshot', async () => {
    const user = userEvent.setup();
    const pending = makeSettings('imx708-720p50', 5_000);
    const snapshot = makeSettingsSnapshot({ pending });
    const controller = makeSettingsController({ snapshot, draft: pending });
    const { rerender } = render(<SettingsActionBar controller={{
      ...controller, dirty: true,
    }} />, { wrapper: LanguageProvider });

    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(controller.save).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: 'Discard pending' })).toBeDisabled();

    rerender(<SettingsActionBar controller={controller} />);
    await user.click(screen.getByRole('button', { name: 'Discard pending' }));
    expect(controller.discard).toHaveBeenCalledOnce();
  });

  it('requires confirmation before applying and restores focus after cancellation', async () => {
    const user = userEvent.setup();
    const pending = makeSettings('imx708-720p50', 5_000);
    const controller = makeSettingsController({
      snapshot: makeSettingsSnapshot({ pending }),
      draft: pending,
    });
    render(<SettingsActionBar controller={controller} />, { wrapper: LanguageProvider });
    const apply = screen.getByRole('button', { name: 'Apply pending' });

    await user.click(apply);
    const dialog = screen.getByRole('alertdialog', { name: 'Apply runtime settings' });
    expect(dialog).toBeVisible();
    expect(screen.getByText(/video and RTSP clients will reconnect briefly/i)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
    await user.keyboard('{Shift>}{Tab}{/Shift}');
    expect(screen.getByRole('button', { name: 'Apply now' })).toHaveFocus();
    await user.keyboard('{Tab}');
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(controller.apply).not.toHaveBeenCalled();
    await waitFor(() => expect(apply).toHaveFocus());
  });

  it('applies only a saved pending snapshot and disables commands while busy', async () => {
    const user = userEvent.setup();
    const pending = makeSettings('imx708-720p50', 5_000);
    const snapshot = makeSettingsSnapshot({ pending });
    const controller = makeSettingsController({ snapshot, draft: pending });
    const { rerender } = render(<SettingsActionBar controller={controller} />, {
      wrapper: LanguageProvider,
    });

    await user.click(screen.getByRole('button', { name: 'Apply pending' }));
    await user.click(screen.getByRole('button', { name: 'Apply now' }));
    expect(controller.apply).toHaveBeenCalledOnce();

    rerender(<SettingsActionBar controller={{ ...controller, status: 'applying' }} />);
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Discard pending' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Applying settings' })).toBeDisabled();
  });

  it('uses bounded notices for failed restore and recovery-required state', () => {
    const failed = makeSettingsSnapshot({
      pending: makeSettings('imx708-720p50', 5_000),
      lastApply: { status: 'failed', code: 'E_SETTINGS_APPLY_FAILED', restored: true },
    });
    const controller = makeSettingsController({
      status: 'error',
      snapshot: failed,
      draft: failed.pending,
      error: { status: 503, code: 'E_SETTINGS_APPLY_FAILED' },
    });
    const { rerender } = render(<SettingsActionBar controller={controller} />, {
      wrapper: LanguageProvider,
    });

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Settings could not be applied. The previous runtime was restored.',
    );
    expect(screen.queryByText('E_SETTINGS_APPLY_FAILED')).not.toBeInTheDocument();

    const recovery = makeSettingsSnapshot({ state: 'recovery_required' });
    rerender(<SettingsActionBar controller={makeSettingsController({
      snapshot: recovery, draft: recovery.active,
    })} />);
    expect(screen.getByRole('status')).toHaveTextContent(
      'Save runtime settings to replace the invalid stored state.',
    );
  });
});
