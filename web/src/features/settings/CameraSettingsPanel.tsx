import type { ChangeEvent } from 'react';

import { SUB_STREAM_RESOLUTIONS } from './contracts';
import type { RuntimeSettingsController } from './useRuntimeSettings';

interface CameraSettingsPanelProps {
  controller: RuntimeSettingsController;
}

const isBusy = (status: RuntimeSettingsController['status']): boolean =>
  status === 'saving' || status === 'applying';

const SUB_STREAM_FPS_OPTIONS = [10, 15, 25, 30] as const;

export function CameraSettingsPanel({
  controller,
}: CameraSettingsPanelProps) {
  const { draft, snapshot } = controller;
  if (draft === null || snapshot === null) {
    return (
      <section className="operational-section settings-section"
        aria-labelledby="camera-settings-heading">
        <div className="section-heading">
          <div>
            <h2 id="camera-settings-heading">Camera settings</h2>
          </div>
        </div>
        <p className="empty-row" role={controller.status === 'error' ? 'alert' : 'status'}>
          {controller.status === 'error'
            ? 'Runtime settings are unavailable.'
            : 'Loading runtime settings...'}
        </p>
      </section>
    );
  }

  const disabled = isBusy(controller.status);
  const subDisabled = disabled || !draft.sub_stream.enabled;
  const updateNumber = (
    field: 'bitrate_kbps' | 'gop',
  ) => (event: ChangeEvent<HTMLInputElement>) => {
    controller.updateCamera({
      ...draft.camera,
      [field]: Number(event.target.value),
    });
  };
  const activeProfile = snapshot.capabilities.camera_profiles.find(
    ({ id }) => id === snapshot.active.camera.profile_id,
  );

  return (
    <section className="operational-section settings-section"
      aria-labelledby="camera-settings-heading">
      <div className="section-heading">
        <div>
          <h2 id="camera-settings-heading">Camera settings</h2>
          <p>
            Active: {activeProfile?.label ?? snapshot.active.camera.profile_id}
            {' / '}{snapshot.active.camera.bitrate_kbps} kbps
            {' / '}GOP {snapshot.active.camera.gop}
          </p>
        </div>
        {snapshot.pending !== null && (
          <span className="settings-state-label">Pending</span>
        )}
      </div>

      <div className="camera-settings-grid">
        <div className="settings-field settings-field-wide">
          <label htmlFor="runtime-camera-profile">Capture profile</label>
          <select
            id="runtime-camera-profile"
            value={draft.camera.profile_id}
            disabled={disabled}
            onChange={(event) => controller.updateCamera({
              ...draft.camera,
              profile_id: event.target.value,
            })}
          >
            {snapshot.capabilities.camera_profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>{profile.label}</option>
            ))}
          </select>
        </div>

        <div className="settings-field">
          <label htmlFor="runtime-camera-bitrate">Bitrate</label>
          <div className="number-control">
            <input
              id="runtime-camera-bitrate"
              type="number"
              min={snapshot.capabilities.bitrate_kbps.minimum}
              max={snapshot.capabilities.bitrate_kbps.maximum}
              step={100}
              value={draft.camera.bitrate_kbps}
              disabled={disabled}
              onChange={updateNumber('bitrate_kbps')}
            />
            <span>kbps</span>
          </div>
        </div>

        <div className="settings-field">
          <label htmlFor="runtime-camera-gop">GOP interval</label>
          <input
            id="runtime-camera-gop"
            type="number"
            min={snapshot.capabilities.gop.minimum}
            max={snapshot.capabilities.gop.maximum}
            step={1}
            value={draft.camera.gop}
            disabled={disabled}
            onChange={updateNumber('gop')}
          />
        </div>
      </div>

      <div className="section-heading">
        <div>
          <h3 id="sub-stream-settings-heading">Sub-stream</h3>
        </div>
      </div>

      <div className="camera-settings-grid">
        <div className="settings-field">
          <label htmlFor="runtime-substream-enabled">Sub-stream</label>
          <input
            id="runtime-substream-enabled"
            type="checkbox"
            checked={draft.sub_stream.enabled}
            disabled={disabled}
            onChange={(event) => controller.updateSubStream({
              ...draft.sub_stream,
              enabled: event.target.checked,
            })}
          />
        </div>

        <div className="settings-field">
          <label htmlFor="runtime-substream-resolution">Resolution</label>
          <select
            id="runtime-substream-resolution"
            value={`${draft.sub_stream.width}x${draft.sub_stream.height}`}
            disabled={subDisabled}
            onChange={(event) => {
              const preset = SUB_STREAM_RESOLUTIONS.find(
                ({ width, height }) => `${width}x${height}` === event.target.value,
              );
              if (preset === undefined) {
                return;
              }
              controller.updateSubStream({
                ...draft.sub_stream,
                width: preset.width,
                height: preset.height,
              });
            }}
          >
            {SUB_STREAM_RESOLUTIONS.map(({ width, height }) => (
              <option key={`${width}x${height}`} value={`${width}x${height}`}>
                {`${width}×${height}`}
              </option>
            ))}
          </select>
        </div>

        <div className="settings-field">
          <label htmlFor="runtime-substream-fps">Frame rate</label>
          <select
            id="runtime-substream-fps"
            value={draft.sub_stream.fps}
            disabled={subDisabled}
            onChange={(event) => controller.updateSubStream({
              ...draft.sub_stream,
              fps: Number(event.target.value),
            })}
          >
            {SUB_STREAM_FPS_OPTIONS.map((fps) => (
              <option key={fps} value={fps}>{fps}</option>
            ))}
          </select>
        </div>

        <div className="settings-field">
          <label htmlFor="runtime-substream-bitrate">Sub-stream bitrate</label>
          <div className="number-control">
            <input
              id="runtime-substream-bitrate"
              type="number"
              min={snapshot.capabilities.bitrate_kbps.minimum}
              max={snapshot.capabilities.bitrate_kbps.maximum}
              step={100}
              value={draft.sub_stream.bitrate_kbps}
              disabled={subDisabled}
              onChange={(event) => controller.updateSubStream({
                ...draft.sub_stream,
                bitrate_kbps: Number(event.target.value),
              })}
            />
            <span>kbps</span>
          </div>
        </div>
      </div>

      <p>
        Applying sub-stream changes briefly interrupts the sub-stream feed.
      </p>
    </section>
  );
}
