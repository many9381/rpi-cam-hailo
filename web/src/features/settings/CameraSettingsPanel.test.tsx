import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { LanguageProvider } from '../../i18n';
import { CameraSettingsPanel } from './CameraSettingsPanel';
import type { RuntimeSettings } from './contracts';
import { makeSettingsController, makeSettingsSnapshot } from './testSupport';

afterEach(cleanup);

const withSubStreamEnabled = (
  base: RuntimeSettings,
  enabled: boolean,
): RuntimeSettings => ({
  ...base,
  sub_stream: { ...base.sub_stream, enabled },
});

describe('CameraSettingsPanel', () => {
  it('offers only approved capture profiles and bounded encoder controls', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

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
    render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

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
    const { rerender } = render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

    expect(screen.getByRole('combobox', { name: 'Capture profile' })).toBeDisabled();
    expect(screen.getByRole('spinbutton', { name: 'Bitrate' })).toBeDisabled();

    rerender(<CameraSettingsPanel controller={{ ...controller, status: 'ready' }} />);
    expect(screen.getByRole('combobox', { name: 'Capture profile' })).toBeEnabled();
    expect(screen.getByRole('spinbutton', { name: 'Bitrate' })).toBeEnabled();
  });

  it('renders the sub-stream enable checkbox reflecting the draft state', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withSubStreamEnabled(snapshot.active, false),
    });
    render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

    expect(screen.getByRole('checkbox', { name: 'Sub-stream' })).not.toBeChecked();
  });

  it('toggles the sub-stream checkbox and calls updateSubStream with enabled flipped', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withSubStreamEnabled(snapshot.active, false),
    });
    render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

    fireEvent.click(screen.getByRole('checkbox', { name: 'Sub-stream' }));
    expect(controller.updateSubStream).toHaveBeenLastCalledWith({
      enabled: true, width: 640, height: 360, fps: 15, bitrate_kbps: 1_000,
    });
  });

  it('enables sub-stream resolution/fps/bitrate controls when enabled and updates via updateSubStream', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withSubStreamEnabled(snapshot.active, true),
    });
    render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

    const resolution = screen.getByRole('combobox', { name: 'Resolution' });
    expect(resolution).toBeEnabled();
    expect(resolution).toHaveValue('640x360');
    expect(screen.getByRole('option', { name: '640×360' })).toBeVisible();
    expect(screen.getByRole('option', { name: '854×480' })).toBeVisible();
    expect(screen.getByRole('option', { name: '1280×720' })).toBeVisible();

    const fps = screen.getByRole('combobox', { name: 'Frame rate' });
    expect(fps).toBeEnabled();
    const bitrate = screen.getByRole('spinbutton', { name: 'Sub-stream bitrate' });
    expect(bitrate).toBeEnabled();
    expect(bitrate).toHaveAttribute('min', '500');
    expect(bitrate).toHaveAttribute('max', '20000');

    fireEvent.change(resolution, { target: { value: '1280x720' } });
    expect(controller.updateSubStream).toHaveBeenLastCalledWith({
      enabled: true, width: 1280, height: 720, fps: 15, bitrate_kbps: 1_000,
    });

    fireEvent.change(fps, { target: { value: '25' } });
    expect(controller.updateSubStream).toHaveBeenLastCalledWith({
      enabled: true, width: 640, height: 360, fps: 25, bitrate_kbps: 1_000,
    });

    fireEvent.change(bitrate, { target: { value: '1500' } });
    expect(controller.updateSubStream).toHaveBeenLastCalledWith({
      enabled: true, width: 640, height: 360, fps: 15, bitrate_kbps: 1_500,
    });
  });

  it('disables sub-stream resolution/fps/bitrate controls when the sub-stream is disabled', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withSubStreamEnabled(snapshot.active, false),
    });
    render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

    expect(screen.getByRole('combobox', { name: 'Resolution' })).toBeDisabled();
    expect(screen.getByRole('combobox', { name: 'Frame rate' })).toBeDisabled();
    expect(screen.getByRole('spinbutton', { name: 'Sub-stream bitrate' })).toBeDisabled();
  });

  it('disables the sub-stream enable checkbox while a settings command is busy', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      status: 'applying',
      snapshot,
      draft: withSubStreamEnabled(snapshot.active, true),
    });
    const { rerender } = render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

    expect(screen.getByRole('checkbox', { name: 'Sub-stream' })).toBeDisabled();

    rerender(<CameraSettingsPanel controller={{ ...controller, status: 'ready' }} />);
    expect(screen.getByRole('checkbox', { name: 'Sub-stream' })).toBeEnabled();
  });
});
