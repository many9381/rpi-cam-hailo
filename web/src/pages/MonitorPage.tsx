import { RefreshCw } from 'lucide-react';

import type { CameraApiClient, DetectionSnapshot } from '../api/types';
import { CameraPreview } from '../components/CameraPreview';
import { IconButton } from '../components/IconButton';
import { useDetectionStream } from '../hooks/useDetectionStream';
import { useMonitoringData } from '../hooks/useMonitoringData';
import { useSnapshot } from '../hooks/useSnapshot';

const emptyDetections: DetectionSnapshot = { events: [] };

export function MonitorPage({ client }: { client: CameraApiClient }) {
  const monitoring = useMonitoringData(client);
  const detections = useDetectionStream(
    emptyDetections,
    monitoring.cameras.length > 0,
  );
  const snapshot = useSnapshot(client, monitoring.selectedCameraId);

  const refreshPage = () => {
    void monitoring.refresh().catch(() => undefined);
    void snapshot.refresh().catch(() => undefined);
  };

  if (monitoring.cameras.length === 0) {
    if (monitoring.state === 'loading') {
      return <section className="monitor-page monitor-state">Loading camera monitoring...</section>;
    }
    return (
      <section className="monitor-page monitor-state">
        <p role="alert">Camera monitoring is unavailable.</p>
        <button type="button" onClick={() => void monitoring.refresh().catch(() => undefined)}>
          Retry
        </button>
      </section>
    );
  }

  const selectedCameraId = monitoring.selectedCameraId;
  return (
    <div className="monitor-page">
      <header className="monitor-heading">
        <h1>Live monitoring</h1>
        <IconButton label="Refresh monitoring and snapshot" onClick={refreshPage}>
          <RefreshCw size={18} aria-hidden="true" />
        </IconButton>
      </header>
      {monitoring.state === 'stale' && (
        <p className="monitor-stale-notice" role="status">Showing last available cameras.</p>
      )}
      <CameraPreview cameras={monitoring.cameras}
        selectedCameraId={selectedCameraId}
        onSelectCamera={monitoring.selectCamera}
        snapshot={detections.snapshot} />
      <section className="monitor-snapshot-section" aria-labelledby="snapshot-heading">
        <div className="section-heading">
          <h2 id="snapshot-heading">Snapshot</h2>
          <IconButton label={`Refresh snapshot for ${selectedCameraId}`}
            onClick={() => void snapshot.refresh().catch(() => undefined)}>
            <RefreshCw size={17} aria-hidden="true" />
          </IconButton>
        </div>
        <div className="monitor-snapshot-stage" aria-busy={snapshot.state === 'loading'}>
          {snapshot.state === 'ready' && snapshot.objectUrl !== null
            ? <img src={snapshot.objectUrl} alt={`${selectedCameraId} camera snapshot`} />
            : <p role="status">{snapshot.state === 'loading'
              ? 'Loading snapshot...'
              : 'Snapshot unavailable.'}</p>}
        </div>
      </section>
    </div>
  );
}
