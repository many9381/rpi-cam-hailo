import type { ChangeEvent } from 'react';

import type { RuntimeSettingsController } from './useRuntimeSettings';

interface AiSettingsPanelProps {
  controller: RuntimeSettingsController;
}

const isBusy = (status: RuntimeSettingsController['status']): boolean =>
  status === 'saving' || status === 'applying';

export function AiSettingsPanel({ controller }: AiSettingsPanelProps) {
  const { draft, snapshot } = controller;
  if (draft === null || snapshot === null) {
    return (
      <section className="operational-section settings-section"
        aria-labelledby="ai-settings-heading">
        <div className="section-heading">
          <div><h2 id="ai-settings-heading">Model settings</h2></div>
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
          <h2 id="ai-settings-heading">Model settings</h2>
          <p>{snapshot.capabilities.models.length} configured models</p>
        </div>
        {snapshot.pending !== null && (
          <span className="settings-state-label">Pending</span>
        )}
      </div>

      {snapshot.capabilities.models.length === 0 ? (
        <p className="empty-row">No AI models configured</p>
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
                      aria-label={`${capability.id} enabled`}
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
                  <div><dt>Kind</dt><dd>{capability.kind}</dd></div>
                  <div><dt>Input</dt><dd>{capability.input_width} x {capability.input_height}</dd></div>
                  <div><dt>Format</dt><dd>{capability.input_format}</dd></div>
                  <div><dt>Resize</dt><dd>{capability.letterbox ? 'Letterbox' : 'Stretch'}</dd></div>
                  <div><dt>Labels</dt><dd>{capability.labels || 'None'}</dd></div>
                </dl>

                <div className="confidence-control">
                  <label htmlFor={`confidence-range-${capability.id}`}>
                    Confidence threshold
                  </label>
                  <div>
                    <input
                      id={`confidence-range-${capability.id}`}
                      type="range"
                      min={0}
                      max={1}
                      step={0.01}
                      value={model.confidence_threshold}
                      aria-label={`${capability.id} confidence`}
                      disabled={disabled}
                      onChange={updateConfidence(capability.id)}
                    />
                    <input
                      type="number"
                      min={0}
                      max={1}
                      step={0.01}
                      value={model.confidence_threshold}
                      aria-label={`${capability.id} confidence value`}
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
