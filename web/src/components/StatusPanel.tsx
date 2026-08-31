import { RotateCw } from 'lucide-react';
import { useRef, useState } from 'react';

import type { CameraStatus, HealthStatus } from '../api/types';
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
          <h2 id="system-status-heading">System and cameras</h2>
          <p>{cameras.length} registered camera{cameras.length === 1 ? '' : 's'}</p>
        </div>
        <div className="section-heading-controls">
          <span className={`status-value status-${health.status === 'ok' ? 'good' : 'warn'}`}>
            {health.status}
          </span>
          {runtimeUnavailable && (
            <IconButton label="Restart camera runtime"
              onClick={() => void restart()} disabled={pending}>
              <RotateCw size={17} aria-hidden="true" />
            </IconButton>
          )}
        </div>
      </div>
      {error && (
        <p className="command-error" role="alert">
          Camera runtime restart failed. Try again.
        </p>
      )}
      <div className="camera-grid">
        {cameras.length === 0 && <p className="empty-row">No cameras registered</p>}
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
              <small>{camera.snapshot_available
                ? 'Snapshot available' : 'Snapshot unavailable'}</small>
              {camera.capture_fps !== undefined && (
                <small className="camera-metrics">
                  {`capture ${camera.capture_fps.toFixed(1)} / `}
                  {`encode ${(camera.encoded_fps ?? 0).toFixed(1)} fps`}
                  {camera.last_encode_ms !== undefined &&
                    ` · ${camera.last_encode_ms.toFixed(1)} ms`}
                </small>
              )}
            </span>
          </label>
        ))}
      </div>
    </section>
  );
}
