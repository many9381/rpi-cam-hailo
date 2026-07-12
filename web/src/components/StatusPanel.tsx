import type { CameraStatus, HealthStatus } from '../api/types';

interface StatusPanelProps {
  health: HealthStatus;
  cameras: CameraStatus[];
  selectedCameraId: string;
  onSelectCamera(id: string): void;
}

export function StatusPanel({ health, cameras, selectedCameraId,
  onSelectCamera }: StatusPanelProps) {
  return (
    <section className="operational-section" aria-labelledby="system-status-heading">
      <div className="section-heading">
        <div>
          <h2 id="system-status-heading">System and cameras</h2>
          <p>{cameras.length} registered camera{cameras.length === 1 ? '' : 's'}</p>
        </div>
        <span className={`status-value status-${health.status === 'ok' ? 'good' : 'warn'}`}>
          {health.status}
        </span>
      </div>
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
            </span>
          </label>
        ))}
      </div>
    </section>
  );
}
