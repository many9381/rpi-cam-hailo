import { RotateCw } from 'lucide-react';
import { useRef, useState } from 'react';

import type { AiStatus, DetectionSnapshot } from '../api/types';
import type { DetectionStreamStatus } from '../hooks/useDetectionStream';
import { IconButton } from './IconButton';

interface AiPanelProps {
  ai: AiStatus;
  detections: DetectionSnapshot;
  streamStatus: DetectionStreamStatus;
  onRestart(): Promise<void>;
}

const streamLabels: Record<DetectionStreamStatus, string> = {
  connecting: 'Connecting',
  live: 'Live',
  reconnecting: 'Reconnecting',
  closed: 'Closed',
};

export function AiPanel({ ai, detections, streamStatus, onRestart }: AiPanelProps) {
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
          <h2 id="ai-heading">Hailo AI runtime</h2>
          <p>{ai.reason}</p>
        </div>
        <div className="ai-heading-controls">
          <span className={`status-value ${ai.enabled ? 'status-good' : 'status-neutral'}`}>
            {ai.enabled ? `${ai.backend} / ${ai.state}` : 'Disabled'}
          </span>
          <IconButton label="Restart AI runtime" onClick={() => void restart()}
            disabled={pending}>
            <RotateCw size={17} aria-hidden="true" />
          </IconButton>
        </div>
      </div>
      {error && <p className="command-error" role="alert">AI restart failed. Try again.</p>}
      <div className="ai-columns">
        <div>
          <h3>Models <span>{ai.model_count}</span></h3>
          <div className="data-list">
            {ai.models.length === 0 && <p className="empty-row">No AI models</p>}
            {ai.models.map((model) => (
              <article className="data-card model-row" key={model.id}>
                <div><strong>{model.id}</strong><span>{model.kind}</span></div>
                <dl>
                  <div><dt>Input</dt><dd>{model.input_width} x {model.input_height} {model.input_format}</dd></div>
                  <div><dt>Resize</dt><dd>{model.letterbox ? 'Letterbox' : 'Direct'}</dd></div>
                  <div><dt>Output</dt><dd>{model.output_name}</dd></div>
                  <div><dt>Threshold</dt><dd>{model.confidence_threshold}</dd></div>
                  <div><dt>Labels</dt><dd>{model.labels}</dd></div>
                </dl>
              </article>
            ))}
          </div>
        </div>
        <div>
          <h3>Runners <span>{ai.runner_count}</span></h3>
          <div className="data-list">
            {ai.runners.length === 0 && <p className="empty-row">No AI runners</p>}
            {ai.runners.map((runner) => (
              <article className={`data-card runner-row ${runner.last_error_code
                ? 'runner-error' : ''}`} key={`${runner.camera_id}:${runner.model_id}`}>
                <div><strong>{runner.model_id}</strong><span>{runner.model_kind}</span></div>
                <p>{runner.camera_id}</p>
                <p>Submitted {runner.submitted_frames} / processed {runner.processed_frames} / dropped {runner.dropped_frames}</p>
                <p>{runner.last_error_code
                  ? `${runner.last_error_code}: ${runner.last_error_message || 'unknown'}`
                  : 'Runner healthy'}</p>
              </article>
            ))}
          </div>
        </div>
      </div>
      <div className="detection-results">
        <h3>
          <span>Detections {detectionRows.length}</span>
          <span className={`detection-stream detection-stream-${streamStatus}`}>
            {streamLabels[streamStatus]}
          </span>
        </h3>
        <div className="data-list">
          {detectionRows.length === 0 && (
            <p className="empty-row">No current detections</p>
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
