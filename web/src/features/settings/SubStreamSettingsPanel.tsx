import { useTranslation } from '../../i18n/LanguageContext';
import {
  SUB_STREAM_RESOLUTIONS,
  type RuntimeSettings,
  type RuntimeSettingsSnapshot,
  type SubStreamRuntimeSettings,
} from './contracts';

interface SubStreamSettingsPanelProps {
  draft: RuntimeSettings;
  snapshot: RuntimeSettingsSnapshot;
  disabled: boolean;
  onChange: (next: SubStreamRuntimeSettings) => void;
}

const SUB_STREAM_FPS_OPTIONS = [10, 15, 25, 30] as const;

export function SubStreamSettingsPanel({
  draft,
  snapshot,
  disabled,
  onChange,
}: SubStreamSettingsPanelProps) {
  const { t } = useTranslation();
  const subDisabled = disabled || !draft.sub_stream.enabled;

  return (
    <>
      <div className="camera-settings-grid">
        <div className="settings-field">
          <label htmlFor="runtime-substream-enabled">{t('settings.subStream')}</label>
          <input
            id="runtime-substream-enabled"
            type="checkbox"
            checked={draft.sub_stream.enabled}
            disabled={disabled}
            onChange={(event) => onChange({
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
              onChange({
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
            onChange={(event) => onChange({
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
              onChange={(event) => onChange({
                ...draft.sub_stream,
                bitrate_kbps: Number(event.target.value),
              })}
            />
            <span>{t('settings.kbps')}</span>
          </div>
        </div>
      </div>

      <p>{t('settings.subStreamApplyNotice')}</p>
    </>
  );
}
