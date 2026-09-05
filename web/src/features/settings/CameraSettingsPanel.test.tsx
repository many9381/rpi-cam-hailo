import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { LanguageProvider } from '../../i18n';
import { CameraSettingsPanel } from './CameraSettingsPanel';
import { MAX_OSD_ITEMS, MAX_OSD_TEXT, type RuntimeSettings } from './contracts';
import { makeSettingsController, makeSettingsSnapshot } from './testSupport';

afterEach(cleanup);

const withSubStreamEnabled = (
  base: RuntimeSettings,
  enabled: boolean,
): RuntimeSettings => ({
  ...base,
  sub_stream: { ...base.sub_stream, enabled },
});

const withOsd = (
  base: RuntimeSettings,
  osd: RuntimeSettings['osd'],
): RuntimeSettings => ({ ...base, osd });

// The panel renders one camera sub-section at a time, chosen by the `section`
// prop (the left-nav sub-tree selects it via the route). Camera is the default.
describe('CameraSettingsPanel sections', () => {
  it('renders only the camera controls for the camera section', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} section="camera" />, { wrapper: LanguageProvider });

    expect(screen.getByRole('heading', { name: 'Camera settings', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Capture profile' })).toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'Sub-stream' })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'Show OSD' })).not.toBeInTheDocument();
  });

  it('renders only the sub-stream controls for the sub_stream section', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withSubStreamEnabled(snapshot.active, true),
    });
    render(<CameraSettingsPanel controller={controller} section="sub_stream" />, { wrapper: LanguageProvider });

    expect(screen.getByRole('heading', { name: 'Sub-stream', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Resolution' })).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Capture profile' })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'Show OSD' })).not.toBeInTheDocument();
  });

  it('renders only the OSD controls for the osd section', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    expect(screen.getByRole('heading', { name: 'OSD', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Show OSD' })).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Capture profile' })).not.toBeInTheDocument();
  });

  it('defaults to the camera section when no section is given', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} />, { wrapper: LanguageProvider });

    expect(screen.getByRole('combobox', { name: 'Capture profile' })).toBeInTheDocument();
  });
});

describe('CameraSettingsPanel', () => {
  it('offers only approved capture profiles and bounded encoder controls', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} section="camera" />, { wrapper: LanguageProvider });

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
    render(<CameraSettingsPanel controller={controller} section="camera" />, { wrapper: LanguageProvider });

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
    const { rerender } = render(<CameraSettingsPanel controller={controller} section="camera" />, { wrapper: LanguageProvider });

    expect(screen.getByRole('combobox', { name: 'Capture profile' })).toBeDisabled();
    expect(screen.getByRole('spinbutton', { name: 'Bitrate' })).toBeDisabled();

    rerender(<CameraSettingsPanel controller={{ ...controller, status: 'ready' }} section="camera" />);
    expect(screen.getByRole('combobox', { name: 'Capture profile' })).toBeEnabled();
    expect(screen.getByRole('spinbutton', { name: 'Bitrate' })).toBeEnabled();
  });

  it('renders the sub-stream enable checkbox reflecting the draft state', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withSubStreamEnabled(snapshot.active, false),
    });
    render(<CameraSettingsPanel controller={controller} section="sub_stream" />, { wrapper: LanguageProvider });

    expect(screen.getByRole('checkbox', { name: 'Sub-stream' })).not.toBeChecked();
  });

  it('toggles the sub-stream checkbox and calls updateSubStream with enabled flipped', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withSubStreamEnabled(snapshot.active, false),
    });
    render(<CameraSettingsPanel controller={controller} section="sub_stream" />, { wrapper: LanguageProvider });

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
    render(<CameraSettingsPanel controller={controller} section="sub_stream" />, { wrapper: LanguageProvider });

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
    render(<CameraSettingsPanel controller={controller} section="sub_stream" />, { wrapper: LanguageProvider });

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
    const { rerender } = render(<CameraSettingsPanel controller={controller} section="sub_stream" />, { wrapper: LanguageProvider });

    expect(screen.getByRole('checkbox', { name: 'Sub-stream' })).toBeDisabled();

    rerender(<CameraSettingsPanel controller={{ ...controller, status: 'ready' }} section="sub_stream" />);
    expect(screen.getByRole('checkbox', { name: 'Sub-stream' })).toBeEnabled();
  });

  it('renders the OSD section with a heading and enabled toggle', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    expect(screen.getByRole('heading', { name: 'OSD', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Show OSD' })).not.toBeChecked();
    expect(screen.getByText('OSD items are drawn on the video after you apply the settings.')).toBeInTheDocument();
    expect(screen.getByText('Dashed items preview unapplied changes; the video shows what is currently applied.')).toBeInTheDocument();
  });

  it('toggles the OSD enabled checkbox and calls updateOsd with enabled flipped', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    fireEvent.click(screen.getByRole('checkbox', { name: 'Show OSD' }));
    expect(controller.updateOsd).toHaveBeenLastCalledWith({ enabled: true, items: [] });
  });

  it('adds a default OSD item and calls updateOsd', () => {
    const controller = makeSettingsController();
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    fireEvent.click(screen.getByRole('button', { name: 'Add item' }));
    expect(controller.updateOsd).toHaveBeenLastCalledWith({
      enabled: false,
      items: [{ type: 'custom_text', text: '', position: 'top_left' }],
    });
  });

  it('edits an OSD item type, text, and position and calls updateOsd with the change', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withOsd(snapshot.active, {
        enabled: true,
        items: [{ type: 'custom_text', text: 'hello', position: 'top_left' }],
      }),
    });
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    fireEvent.change(screen.getByRole('combobox', { name: 'Type' }), {
      target: { value: 'timestamp' },
    });
    expect(controller.updateOsd).toHaveBeenLastCalledWith({
      enabled: true,
      items: [{ type: 'timestamp', text: 'hello', position: 'top_left' }],
    });

    fireEvent.change(screen.getByRole('textbox', { name: 'Text' }), {
      target: { value: 'world' },
    });
    expect(controller.updateOsd).toHaveBeenLastCalledWith({
      enabled: true,
      items: [{ type: 'custom_text', text: 'world', position: 'top_left' }],
    });

    fireEvent.change(screen.getByRole('combobox', { name: 'Position' }), {
      target: { value: 'bottom_right' },
    });
    expect(controller.updateOsd).toHaveBeenLastCalledWith({
      enabled: true,
      items: [{ type: 'custom_text', text: 'hello', position: 'bottom_right' }],
    });
  });

  it('removes an OSD item and calls updateOsd without it', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withOsd(snapshot.active, {
        enabled: true,
        items: [
          { type: 'custom_text', text: 'first', position: 'top_left' },
          { type: 'camera_name', text: '', position: 'bottom_right' },
        ],
      }),
    });
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    fireEvent.click(screen.getAllByRole('button', { name: 'Remove' })[0]);
    expect(controller.updateOsd).toHaveBeenLastCalledWith({
      enabled: true,
      items: [{ type: 'camera_name', text: '', position: 'bottom_right' }],
    });
  });

  it('flags an empty custom text item as invalid until text is entered', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withOsd(snapshot.active, {
        enabled: true,
        items: [
          { type: 'custom_text', text: '', position: 'top_left' },
          { type: 'custom_text', text: 'Front door', position: 'top_right' },
        ],
      }),
    });
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    const [empty, filled] = screen.getAllByRole('textbox', { name: 'Text' });
    expect(empty).toHaveAttribute('aria-invalid', 'true');
    expect(empty).toHaveAccessibleDescription('Enter the text to display.');
    expect(filled).not.toHaveAttribute('aria-invalid');
    expect(screen.getAllByText('Enter the text to display.')).toHaveLength(1);
  });

  it('shows the UTF-8 byte usage and flags custom text over 64 bytes', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withOsd(snapshot.active, {
        enabled: true,
        items: [
          { type: 'custom_text', text: 'Front door', position: 'top_left' },
          { type: 'custom_text', text: '가'.repeat(22), position: 'top_right' },  // 66 bytes
        ],
      }),
    });
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    const [fits, over] = screen.getAllByRole('textbox', { name: 'Text' });
    expect(fits).not.toHaveAttribute('aria-invalid');
    expect(screen.getByText('10/64 bytes')).toHaveClass('settings-field-hint');
    expect(over).toHaveAttribute('aria-invalid', 'true');
    expect(over).toHaveAccessibleDescription('66/64 bytes — the limit is 64 UTF-8 bytes.');
  });

  it('disables Add item once MAX_OSD_ITEMS items are present', () => {
    const snapshot = makeSettingsSnapshot();
    const items = Array.from({ length: MAX_OSD_ITEMS }, () => ({
      type: 'custom_text' as const, text: 'x', position: 'top_left' as const,
    }));
    const controller = makeSettingsController({
      snapshot,
      draft: withOsd(snapshot.active, { enabled: true, items }),
    });
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    expect(screen.getByRole('button', { name: 'Add item' })).toBeDisabled();
  });

  it('enforces MAX_OSD_TEXT on the OSD item text input', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      snapshot,
      draft: withOsd(snapshot.active, {
        enabled: true,
        items: [{ type: 'custom_text', text: '', position: 'top_left' }],
      }),
    });
    render(<CameraSettingsPanel controller={controller} section="osd" />, { wrapper: LanguageProvider });

    const textInput = screen.getByRole('textbox', { name: 'Text' }) as HTMLInputElement;
    expect(textInput.maxLength).toBe(MAX_OSD_TEXT);
  });
});
