import { RotateCw } from 'lucide-react';
import { useRef, useState } from 'react';

import type { CameraStatus, HealthStatus } from '../api/types';
import { useTranslation } from '../i18n/LanguageContext';
import { IconButton } from './IconButton';

interface StatusPanelProps {
  health: HealthStatus;
  cameras: CameraStatus[];
  selectedCameraId: string;
  onSelectCamera(id: string): void;
  onRestartRuntime(): Promise<void>;
}

export function StatusPanel({ health, cameras, selectedCameraId,
  onSelectCamera, onRestartRuntime }: StatusPanelProps) {
  const { t } = useTranslation();
  const pendingRef = useRef(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);
  const runtimeUnavailable = cameras.some(
    ({ state }) => state === 'error' || state === 'stopped',
  );

  const restart = async () => {
    if (pendingRef.current) {
      return;
    }
    pendingRef.current = true;
    setPending(true);
    setError(false);
    try {
      await onRestartRuntime();
    } catch {
      setError(true);
    } finally {
      pendingRef.current = false;
      setPending(false);
    }
  };

  return (
    <section className="operational-section" aria-labelledby="system-status-heading">
      <div className="section-heading">
        <div>
          <h2 id="system-status-heading">{t('status.title')}</h2>
          <p>{t(cameras.length === 1 ? 'status.registeredCameraOne' : 'status.registeredCameraOther',
            { n: cameras.length })}</p>
        </div>
        <div className="section-heading-controls">
          <span className={`status-value status-${health.status === 'ok' ? 'good' : 'warn'}`}>
            {health.status}
          </span>
          {runtimeUnavailable && (
            <IconButton label={t('status.restartRuntime')}
              onClick={() => void restart()} disabled={pending}>
              <RotateCw size={17} aria-hidden="true" />
            </IconButton>
          )}
        </div>
      </div>
      {error && (
        <p className="command-error" role="alert">
          {t('status.restartFailed')}
        </p>
      )}
      <div className="camera-grid">
        {cameras.length === 0 && <p className="empty-row">{t('status.noCameras')}</p>}
        {cameras.map((camera) => (
          <label className="data-card camera-card" key={camera.id}>
            <input
              type="radio"
              name="selected-camera"
              checked={selectedCameraId === camera.id}
              onChange={() => onSelectCamera(camera.id)}
            />
            <span className="camera-card-content">
              <strong>{camera.id}</strong>
              <span>{camera.state}</span>
              {camera.capture_error && (
                <small role="status">
                  {t(camera.capture_error === 'E_CAMERA_NO_FRAMES'
                    ? 'status.noCameraFrames'
                    : camera.capture_error === 'E_CAMERA_CAPTURE_STALLED'
                      ? 'status.captureStalled' : 'status.captureFailed')}
                </small>
              )}
              {camera.state === 'recovering' && (
                <small>{t('status.recoveringCapture', {
                  n: camera.recovery_attempts ?? 0, max: camera.recovery_limit ?? 3,
                })}</small>
              )}
              {camera.state === 'error' && camera.capture_error && (
                <small>{t('status.captureRecoveryStopped')}</small>
              )}
              <small>{camera.snapshot_available
                ? t('status.snapshotAvailable') : t('status.snapshotUnavailable')}</small>
              {camera.capture_fps !== undefined && (
                <small className="camera-metrics">
                  {camera.last_encode_ms !== undefined
                    ? t('status.cameraMetricsWithMs', {
                      capture: camera.capture_fps.toFixed(1),
                      encode: (camera.encoded_fps ?? 0).toFixed(1),
                      ms: camera.last_encode_ms.toFixed(1),
                    })
                    : t('status.cameraMetrics', {
                      capture: camera.capture_fps.toFixed(1),
                      encode: (camera.encoded_fps ?? 0).toFixed(1),
                    })}
                </small>
              )}
            </span>
          </label>
        ))}
      </div>
    </section>
  );
}
