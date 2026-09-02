import { useTranslation } from '../../i18n/LanguageContext';
import {
  MAX_OSD_ITEMS,
  MAX_OSD_TEXT,
  OSD_ITEM_TYPES,
  OSD_POSITIONS,
  type OsdItem,
  type OsdItemType,
  type OsdPosition,
  type OsdRuntimeSettings,
} from './contracts';

interface OsdSettingsPanelProps {
  osd: OsdRuntimeSettings;
  disabled: boolean;
  onChange: (next: OsdRuntimeSettings) => void;
}

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

export function OsdSettingsPanel({ osd, disabled, onChange }: OsdSettingsPanelProps) {
  const { t } = useTranslation();

  const updateOsdItem = (index: number, patch: Partial<OsdItem>) => {
    onChange({
      enabled: osd.enabled,
      items: osd.items.map(
        (item, itemIndex) => (itemIndex === index ? { ...item, ...patch } : item),
      ),
    });
  };
  const removeOsdItem = (index: number) => {
    onChange({
      enabled: osd.enabled,
      items: osd.items.filter((_item, itemIndex) => itemIndex !== index),
    });
  };
  const addOsdItem = () => {
    onChange({
      enabled: osd.enabled,
      items: [...osd.items, makeDefaultOsdItem()],
    });
  };

  return (
    <>
      <div className="camera-settings-grid">
        <div className="settings-field">
          <label htmlFor="runtime-osd-enabled">{t('osd.enable')}</label>
          <input
            id="runtime-osd-enabled"
            type="checkbox"
            checked={osd.enabled}
            disabled={disabled}
            onChange={(event) => onChange({
              ...osd,
              enabled: event.target.checked,
            })}
          />
        </div>
      </div>

      <div className="model-settings-list">
        {osd.items.map((item, index) => (
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
        disabled={disabled || osd.items.length >= MAX_OSD_ITEMS}
        onClick={addOsdItem}
      >
        {t('osd.addItem')}
      </button>

      <p>{t('osd.applyNotice')}</p>
    </>
  );
}
