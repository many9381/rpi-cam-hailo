import type { ChangeEvent } from 'react';

import { useTranslation } from '../../i18n/LanguageContext';
import type { RuntimeSettingsController } from './useRuntimeSettings';

interface AiSettingsPanelProps {
  controller: RuntimeSettingsController;
}

const isBusy = (status: RuntimeSettingsController['status']): boolean =>
  status === 'saving' || status === 'applying';

export function AiSettingsPanel({ controller }: AiSettingsPanelProps) {
  const { t } = useTranslation();
  const { draft, snapshot } = controller;
  if (draft === null || snapshot === null) {
    return (
      <section className="operational-section settings-section"
        aria-labelledby="ai-settings-heading">
        <div className="section-heading">
          <div><h2 id="ai-settings-heading">{t('settings.modelSettingsHeading')}</h2></div>
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
  const updateConfidence = (id: string) => (
    event: ChangeEvent<HTMLInputElement>,
  ) => controller.updateModel(id, {
    confidence_threshold: Number(event.target.value),
  });

  return (
    <section className="operational-section settings-section"
      aria-labelledby="ai-settings-heading">
      <div className="section-heading">
        <div>
          <h2 id="ai-settings-heading">{t('settings.modelSettingsHeading')}</h2>
          <p>{t('settings.configuredModels', { count: snapshot.capabilities.models.length })}</p>
        </div>
        {snapshot.pending !== null && (
          <span className="settings-state-label">{t('settings.pendingLabel')}</span>
        )}
      </div>

      {snapshot.capabilities.models.length === 0 ? (
        <p className="empty-row">{t('settings.noModelsConfigured')}</p>
      ) : (
        <div className="model-settings-list">
          {snapshot.capabilities.models.map((capability) => {
            const model = draft.models.find(({ id }) => id === capability.id);
            if (model === undefined) {
              return null;
            }
            return (
              <div className="model-settings-row" key={capability.id}>
                <div className="model-settings-header">
                  <div>
                    <strong>{capability.id}</strong>
                  </div>
                  <label className="switch-control">
                    <input
                      type="checkbox"
                      role="switch"
                      aria-label={t('settings.modelEnabledLabel', { id: capability.id })}
                      checked={model.enabled}
                      disabled={disabled}
                      onChange={(event) => controller.updateModel(capability.id, {
                        enabled: event.target.checked,
                      })}
                    />
                    <span aria-hidden="true" />
                  </label>
                </div>

                <dl className="model-capabilities">
                  <div><dt>{t('settings.kind')}</dt><dd>{capability.kind}</dd></div>
                  <div><dt>{t('ai.input')}</dt><dd>{capability.input_width} x {capability.input_height}</dd></div>
                  <div><dt>{t('settings.format')}</dt><dd>{capability.input_format}</dd></div>
                  <div><dt>{t('ai.resize')}</dt><dd>{capability.letterbox ? t('ai.letterbox') : t('settings.stretch')}</dd></div>
                  <div><dt>{t('ai.labels')}</dt><dd>{capability.labels || t('settings.none')}</dd></div>
                </dl>

                <div className="confidence-control">
                  <label htmlFor={`confidence-range-${capability.id}`}>
                    {t('settings.confidenceThreshold')}
                  </label>
                  <div>
                    <input
                      id={`confidence-range-${capability.id}`}
                      type="range"
                      min={0}
                      max={1}
                      step={0.01}
                      value={model.confidence_threshold}
                      aria-label={t('settings.modelConfidenceLabel', { id: capability.id })}
                      disabled={disabled}
                      onChange={updateConfidence(capability.id)}
                    />
                    <input
                      type="number"
                      min={0}
                      max={1}
                      step={0.01}
                      value={model.confidence_threshold}
                      aria-label={t('settings.modelConfidenceValueLabel', { id: capability.id })}
                      disabled={disabled}
                      onChange={updateConfidence(capability.id)}
                    />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
