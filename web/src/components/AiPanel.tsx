import { RotateCw } from 'lucide-react';
import { useRef, useState } from 'react';

import type { AiStatus, DetectionSnapshot } from '../api/types';
import type { DetectionStreamStatus } from '../hooks/useDetectionStream';
import { useTranslation } from '../i18n/LanguageContext';
import { IconButton } from './IconButton';

interface AiPanelProps {
  ai: AiStatus;
  detections: DetectionSnapshot;
  streamStatus: DetectionStreamStatus;
  onRestart(): Promise<void>;
}

const streamStatusKeys: Record<DetectionStreamStatus, string> = {
  connecting: 'ai.streamConnecting',
  live: 'ai.streamLive',
  reconnecting: 'ai.streamReconnecting',
  closed: 'ai.streamClosed',
};

export function AiPanel({ ai, detections, streamStatus, onRestart }: AiPanelProps) {
  const { t } = useTranslation();
  const pendingRef = useRef(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);
  const detectionRows = detections.events.flatMap((event) =>
    event.detections.map((detection, index) => ({ event, detection, index })));

  const restart = async () => {
    if (pendingRef.current) {
      return;
    }
    pendingRef.current = true;
    setPending(true);
    setError(false);
    try {
      await onRestart();
    } catch {
      setError(true);
    } finally {
      pendingRef.current = false;
      setPending(false);
    }
  };

  return (
    <section className="operational-section" aria-labelledby="ai-heading">
      <div className="section-heading">
        <div>
          <h2 id="ai-heading">{t('ai.title')}</h2>
          <p>{ai.reason}</p>
        </div>
        <div className="ai-heading-controls">
          <span className={`status-value ${ai.enabled ? 'status-good' : 'status-neutral'}`}>
            {ai.enabled ? `${ai.backend} / ${ai.state}` : t('ai.disabled')}
          </span>
          <IconButton label={t('ai.restartRuntime')} onClick={() => void restart()}
            disabled={pending}>
            <RotateCw size={17} aria-hidden="true" />
          </IconButton>
        </div>
      </div>
      {error && <p className="command-error" role="alert">{t('ai.restartFailed')}</p>}
      <div className="ai-columns">
        <div>
          <h3>{t('ai.models')} <span>{ai.model_count}</span></h3>
          <div className="data-list">
            {ai.models.length === 0 && <p className="empty-row">{t('ai.noModels')}</p>}
            {ai.models.map((model) => (
              <article className="data-card model-row" key={model.id}>
                <div><strong>{model.id}</strong><span>{model.kind}</span></div>
                <dl>
                  <div><dt>{t('ai.input')}</dt><dd>{model.input_width} x {model.input_height} {model.input_format}</dd></div>
                  <div><dt>{t('ai.resize')}</dt><dd>{model.letterbox ? t('ai.letterbox') : t('ai.direct')}</dd></div>
                  <div><dt>{t('ai.output')}</dt><dd>{model.output_name}</dd></div>
                  <div><dt>{t('ai.threshold')}</dt><dd>{model.confidence_threshold}</dd></div>
                  <div><dt>{t('ai.labels')}</dt><dd>{model.labels}</dd></div>
                </dl>
              </article>
            ))}
          </div>
        </div>
        <div>
          <h3>{t('ai.runners')} <span>{ai.runner_count}</span></h3>
          <div className="data-list">
            {ai.runners.length === 0 && <p className="empty-row">{t('ai.noRunners')}</p>}
            {ai.runners.map((runner) => (
              <article className={`data-card runner-row ${runner.last_error_code
                ? 'runner-error' : ''}`} key={`${runner.camera_id}:${runner.model_id}`}>
                <div><strong>{runner.model_id}</strong><span>{runner.model_kind}</span></div>
                <p>{runner.camera_id}</p>
                <p>{t('ai.submittedProcessedDropped', {
                  submitted: runner.submitted_frames,
                  processed: runner.processed_frames,
                  dropped: runner.dropped_frames,
                })}</p>
                <p>{t('ai.frameStats', {
                  sequence: runner.last_processed_sequence,
                  preprocess: runner.last_preprocess_ms.toFixed(1),
                  inference: runner.last_inference_ms.toFixed(1),
                })}</p>
                <p>{runner.last_error_code
                  ? t('ai.runnerErrorFormat', {
                    code: runner.last_error_code,
                    message: runner.last_error_message || t('ai.unknownError'),
                  })
                  : t('ai.runnerHealthy')}</p>
              </article>
            ))}
          </div>
        </div>
      </div>
      <div className="detection-results">
        <h3>
          <span>{t('ai.detections')} {detectionRows.length}</span>
          <span className={`detection-stream detection-stream-${streamStatus}`}>
            {t(streamStatusKeys[streamStatus])}
          </span>
        </h3>
        <div className="data-list">
          {detectionRows.length === 0 && (
            <p className="empty-row">{t('ai.noDetections')}</p>
          )}
          {detectionRows.map(({ event, detection, index }) => (
            <p className="detection-row"
              key={`${event.camera_id}:${event.model_id}:${event.frame_sequence}:${index}`}>
              <strong>{event.model_id}</strong>
              <span>{detection.label}</span>
              <span>{Math.round(detection.confidence * 100)}%</span>
            </p>
          ))}
        </div>
      </div>
    </section>
  );
}
