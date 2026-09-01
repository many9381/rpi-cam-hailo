import type { ChangeEvent } from 'react';

import { useTranslation } from '../../i18n/LanguageContext';
import {
  MAX_OSD_ITEMS,
  MAX_OSD_TEXT,
  OSD_ITEM_TYPES,
  OSD_POSITIONS,
  SUB_STREAM_RESOLUTIONS,
  type OsdItem,
  type OsdItemType,
  type OsdPosition,
} from './contracts';
import type { RuntimeSettingsController } from './useRuntimeSettings';

interface CameraSettingsPanelProps {
  controller: RuntimeSettingsController;
}

const isBusy = (status: RuntimeSettingsController['status']): boolean =>
  status === 'saving' || status === 'applying';

const SUB_STREAM_FPS_OPTIONS = [10, 15, 25, 30] as const;

const OSD_TYPE_LABEL_KEYS: Record<OsdItemType, string> = {
  timestamp: 'osd.typeTimestamp',
  camera_name: 'osd.typeCameraName',
  custom_text: 'osd.typeCustomText',
};

const OSD_POSITION_LABEL_KEYS: Record<OsdPosition, string> = {
  top_left: 'osd.posTopLeft',
  top_right: 'osd.posTopRight',
  bottom_left: 'osd.posBottomLeft',
  bottom_right: 'osd.posBottomRight',
};

// A factory (not a shared constant) so every "Add item" click produces its
// own object identity - items are never mutated in place, but a hoisted
// singleton could still end up referenced by more than one array slot.
const makeDefaultOsdItem = (): OsdItem => ({
  type: 'custom_text',
  text: '',
  position: 'top_left',
});

export function CameraSettingsPanel({
  controller,
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

  const updateOsdItem = (index: number, patch: Partial<OsdItem>) => {
    controller.updateOsd({
      enabled: draft.osd.enabled,
      items: draft.osd.items.map(
        (item, itemIndex) => (itemIndex === index ? { ...item, ...patch } : item),
      ),
    });
  };
  const removeOsdItem = (index: number) => {
    controller.updateOsd({
      enabled: draft.osd.enabled,
      items: draft.osd.items.filter((_item, itemIndex) => itemIndex !== index),
    });
  };
  const addOsdItem = () => {
    controller.updateOsd({
      enabled: draft.osd.enabled,
      items: [...draft.osd.items, makeDefaultOsdItem()],
    });
  };

  return (
    <section className="operational-section settings-section"
      aria-labelledby="camera-settings-heading">
      <div className="section-heading">
        <div>
          <h2 id="camera-settings-heading">{t('settings.cameraSettingsHeading')}</h2>
          <p>
            {t('settings.activeCameraSummary', {
              profile: activeProfile?.label ?? snapshot.active.camera.profile_id,
              bitrate: snapshot.active.camera.bitrate_kbps,
              gop: snapshot.active.camera.gop,
            })}
          </p>
        </div>
        {snapshot.pending !== null && (
          <span className="settings-state-label">{t('settings.pendingLabel')}</span>
        )}
      </div>

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

      <div className="section-heading">
        <div>
          <h3 id="sub-stream-settings-heading">{t('settings.subStream')}</h3>
        </div>
      </div>

      <div className="camera-settings-grid">
        <div className="settings-field">
          <label htmlFor="runtime-substream-enabled">{t('settings.subStream')}</label>
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
          <label htmlFor="runtime-substream-resolution">{t('settings.resolution')}</label>
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
          <label htmlFor="runtime-substream-fps">{t('settings.frameRate')}</label>
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
          <label htmlFor="runtime-substream-bitrate">{t('settings.subStreamBitrate')}</label>
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
            <span>{t('settings.kbps')}</span>
          </div>
        </div>
      </div>

      <p>{t('settings.subStreamApplyNotice')}</p>

      <section aria-labelledby="osd-settings-heading">
        <div className="section-heading">
          <div>
            <h3 id="osd-settings-heading">{t('osd.heading')}</h3>
          </div>
        </div>

        <div className="camera-settings-grid">
          <div className="settings-field">
            <label htmlFor="runtime-osd-enabled">{t('osd.enable')}</label>
            <input
              id="runtime-osd-enabled"
              type="checkbox"
              checked={draft.osd.enabled}
              disabled={disabled}
              onChange={(event) => controller.updateOsd({
                ...draft.osd,
                enabled: event.target.checked,
              })}
            />
          </div>
        </div>

        <div className="model-settings-list">
          {draft.osd.items.map((item, index) => (
            // OsdItem has no stable id (Task 4 contract); index is the only key available,
            // acceptable here since the list is small, fully controlled, and never reordered.
            <div className="model-settings-row" key={index}>
              <div className="settings-field">
                <label htmlFor={`runtime-osd-item-${index}-type`}>{t('osd.type')}</label>
                <select
                  id={`runtime-osd-item-${index}-type`}
                  value={item.type}
                  disabled={disabled}
                  onChange={(event) => updateOsdItem(index, {
                    type: event.target.value as OsdItemType,
                  })}
                >
                  {OSD_ITEM_TYPES.map((type) => (
                    <option key={type} value={type}>{t(OSD_TYPE_LABEL_KEYS[type])}</option>
                  ))}
                </select>
              </div>

              {item.type !== 'camera_name' && (
                <div className="settings-field">
                  <label htmlFor={`runtime-osd-item-${index}-text`}>{t('osd.text')}</label>
                  <input
                    id={`runtime-osd-item-${index}-text`}
                    type="text"
                    maxLength={MAX_OSD_TEXT}
                    value={item.text}
                    placeholder={item.type === 'timestamp'
                      ? t('osd.timestampFormatPlaceholder')
                      : undefined}
                    disabled={disabled}
                    onChange={(event) => updateOsdItem(index, { text: event.target.value })}
                  />
                </div>
              )}

              <div className="settings-field">
                <label htmlFor={`runtime-osd-item-${index}-position`}>{t('osd.position')}</label>
                <select
                  id={`runtime-osd-item-${index}-position`}
                  value={item.position}
                  disabled={disabled}
                  onChange={(event) => updateOsdItem(index, {
                    position: event.target.value as OsdPosition,
                  })}
                >
                  {OSD_POSITIONS.map((position) => (
                    <option key={position} value={position}>
                      {t(OSD_POSITION_LABEL_KEYS[position])}
                    </option>
                  ))}
                </select>
              </div>

              <button type="button" disabled={disabled} onClick={() => removeOsdItem(index)}>
                {t('osd.remove')}
              </button>
            </div>
          ))}
        </div>

        <button
          type="button"
          disabled={disabled || draft.osd.items.length >= MAX_OSD_ITEMS}
          onClick={addOsdItem}
        >
          {t('osd.addItem')}
        </button>

        <p>{t('osd.applyNotice')}</p>
      </section>
    </section>
  );
}
