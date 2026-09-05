import type { ChangeEvent } from 'react';

import { useTranslation } from '../../i18n/LanguageContext';
import { OsdSettingsPanel } from './OsdSettingsPanel';
import { SubStreamSettingsPanel } from './SubStreamSettingsPanel';
import type { RuntimeSettingsController } from './useRuntimeSettings';

// Which camera sub-section this panel shows. Selected by the left-nav sub-tree
// (Camera / Sub-stream / OSD) via the route, not by an in-panel control.
export type CameraSettingsSection = 'camera' | 'sub_stream' | 'osd';

interface CameraSettingsPanelProps {
  controller: RuntimeSettingsController;
  section?: CameraSettingsSection;
}

const isBusy = (status: RuntimeSettingsController['status']): boolean =>
  status === 'saving' || status === 'applying';

const SECTION_HEADING_KEYS: Record<CameraSettingsSection, string> = {
  camera: 'settings.cameraSettingsHeading',
  sub_stream: 'settings.subStream',
  osd: 'osd.heading',
};

export function CameraSettingsPanel({
  controller,
  section = 'camera',
}: CameraSettingsPanelProps) {
  const { t } = useTranslation();
  const { draft, snapshot } = controller;
  if (draft === null || snapshot === null) {
    return (
      <section className="operational-section settings-section"
        aria-labelledby="camera-settings-heading">
        <div className="section-heading">
          <div>
            <h2 id="camera-settings-heading">{t('settings.cameraSettingsHeading')}</h2>
          </div>
        </div>
        <p className="empty-row" role={controller.status === 'error' ? 'alert' : 'status'}>
          {controller.status === 'error'
            ? t('settings.unavailable')
            : t('settings.loading')}
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
          <h2 id="camera-settings-heading">{t(SECTION_HEADING_KEYS[section])}</h2>
          {section === 'camera' && (
            <p>
              {t('settings.activeCameraSummary', {
                profile: activeProfile?.label ?? snapshot.active.camera.profile_id,
                bitrate: snapshot.active.camera.bitrate_kbps,
                gop: snapshot.active.camera.gop,
              })}
            </p>
          )}
        </div>
        {snapshot.pending !== null && (
          <span className="settings-state-label">{t('settings.pendingLabel')}</span>
        )}
      </div>

      {section === 'camera' && (
        <div className="camera-settings-grid">
          <div className="settings-field settings-field-wide">
            <label htmlFor="runtime-camera-profile">{t('settings.captureProfile')}</label>
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
            <label htmlFor="runtime-camera-bitrate">{t('settings.bitrate')}</label>
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
              <span>{t('settings.kbps')}</span>
            </div>
          </div>

          <div className="settings-field">
            <label htmlFor="runtime-camera-gop">{t('settings.gopInterval')}</label>
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
      )}

      {section === 'sub_stream' && (
        <SubStreamSettingsPanel
          draft={draft}
          snapshot={snapshot}
          disabled={disabled}
          onChange={controller.updateSubStream}
        />
      )}

      {section === 'osd' && (
        <OsdSettingsPanel
          osd={draft.osd}
          disabled={disabled}
          onChange={controller.updateOsd}
        />
      )}
    </section>
  );
}
