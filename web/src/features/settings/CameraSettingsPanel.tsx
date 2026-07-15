import type { ChangeEvent } from 'react';

import type { RuntimeSettingsController } from './useRuntimeSettings';

interface CameraSettingsPanelProps {
  controller: RuntimeSettingsController;
}

const isBusy = (status: RuntimeSettingsController['status']): boolean =>
  status === 'saving' || status === 'applying';

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
    </section>
  );
}
