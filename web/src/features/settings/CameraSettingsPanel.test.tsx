import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { CameraSettingsPanel } from './CameraSettingsPanel';
import { makeSettingsController, makeSettingsSnapshot } from './testSupport';

afterEach(cleanup);

describe('CameraSettingsPanel', () => {
  it('offers only approved capture profiles and bounded encoder controls', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} />);

    const profile = screen.getByRole('combobox', { name: 'Capture profile' });
    expect(profile).toHaveValue('imx708-1080p50');
    expect(profile.querySelectorAll('option')).toHaveLength(3);
    expect(screen.getByRole('option', { name: '1080p / 50 fps' })).toBeVisible();
    expect(screen.getByRole('option', { name: '1080p / 30 fps' })).toBeVisible();
    expect(screen.getByRole('option', { name: '720p / 50 fps' })).toBeVisible();

    const bitrate = screen.getByRole('spinbutton', { name: 'Bitrate' });
    expect(bitrate).toHaveAttribute('min', '500');
    expect(bitrate).toHaveAttribute('max', '20000');
    const gop = screen.getByRole('spinbutton', { name: 'GOP interval' });
    expect(gop).toHaveAttribute('min', '1');
    expect(gop).toHaveAttribute('max', '300');
    expect(screen.queryByRole('spinbutton', { name: /width|height|frame rate/i }))
      .not.toBeInTheDocument();
  });

  it('updates profile, bitrate, and GOP through the shared draft controller', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} />);

    fireEvent.change(screen.getByRole('combobox', { name: 'Capture profile' }), {
      target: { value: 'imx708-720p50' },
    });
    expect(controller.updateCamera).toHaveBeenLastCalledWith({
      profile_id: 'imx708-720p50', bitrate_kbps: 6_000, gop: 25,
    });

    fireEvent.change(screen.getByRole('spinbutton', { name: 'Bitrate' }), {
      target: { value: '7500' },
    });
    expect(controller.updateCamera).toHaveBeenLastCalledWith({
      profile_id: 'imx708-1080p50', bitrate_kbps: 7_500, gop: 25,
    });

    fireEvent.change(screen.getByRole('spinbutton', { name: 'GOP interval' }), {
      target: { value: '50' },
    });
    expect(controller.updateCamera).toHaveBeenLastCalledWith({
      profile_id: 'imx708-1080p50', bitrate_kbps: 6_000, gop: 50,
    });
  });

  it('disables camera controls only while a settings command is active', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      status: 'applying',
      snapshot,
      draft: { ...snapshot.active, models: snapshot.active.models.map((model) => ({
        ...model, enabled: false,
      })) },
    });
    const { rerender } = render(<CameraSettingsPanel controller={controller} />);

    expect(screen.getByRole('combobox', { name: 'Capture profile' })).toBeDisabled();
    expect(screen.getByRole('spinbutton', { name: 'Bitrate' })).toBeDisabled();

    rerender(<CameraSettingsPanel controller={{ ...controller, status: 'ready' }} />);
    expect(screen.getByRole('combobox', { name: 'Capture profile' })).toBeEnabled();
    expect(screen.getByRole('spinbutton', { name: 'Bitrate' })).toBeEnabled();
  });
});
