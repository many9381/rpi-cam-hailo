import { RefreshCw } from 'lucide-react';

import type { CameraApiClient, DetectionSnapshot } from '../api/types';
import { CameraPreview } from '../components/CameraPreview';
import { IconButton } from '../components/IconButton';
import { useDetectionStream } from '../hooks/useDetectionStream';
import { useMonitoringData } from '../hooks/useMonitoringData';
import { useSnapshot } from '../hooks/useSnapshot';
import { useTranslation } from '../i18n/LanguageContext';

const emptyDetections: DetectionSnapshot = { events: [] };

export function MonitorPage({ client }: { client: CameraApiClient }) {
  const { t } = useTranslation();
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
      return <section className="monitor-page monitor-state">{t('monitor.loading')}</section>;
    }
    return (
      <section className="monitor-page monitor-state">
        <p role="alert">{t('monitor.unavailable')}</p>
        <button type="button" onClick={() => void monitoring.refresh().catch(() => undefined)}>
          {t('common.retry')}
        </button>
      </section>
    );
  }

  const selectedCameraId = monitoring.selectedCameraId;
  return (
    <div className="monitor-page">
      <header className="monitor-heading">
        <h1>{t('monitor.title')}</h1>
        <IconButton label={t('monitor.refreshMonitoring')} onClick={refreshPage}>
          <RefreshCw size={18} aria-hidden="true" />
        </IconButton>
      </header>
      {monitoring.state === 'stale' && (
        <p className="monitor-stale-notice" role="status">{t('monitor.staleNotice')}</p>
      )}
      <CameraPreview cameras={monitoring.cameras}
        selectedCameraId={selectedCameraId}
        onSelectCamera={monitoring.selectCamera}
        snapshot={detections.snapshot} />
      <section className="monitor-snapshot-section" aria-labelledby="snapshot-heading">
        <div className="section-heading">
          <h2 id="snapshot-heading">{t('monitor.snapshotHeading')}</h2>
          <IconButton label={t('monitor.refreshSnapshotFor', { id: selectedCameraId })}
            onClick={() => void snapshot.refresh().catch(() => undefined)}>
            <RefreshCw size={17} aria-hidden="true" />
          </IconButton>
        </div>
        <div className="monitor-snapshot-stage" aria-busy={snapshot.state === 'loading'}>
          {snapshot.state === 'ready' && snapshot.objectUrl !== null
            ? <img src={snapshot.objectUrl} alt={t('monitor.cameraSnapshotAlt', { id: selectedCameraId })} />
            : <p role="status">{snapshot.state === 'loading'
              ? t('monitor.loadingSnapshot')
              : t('monitor.snapshotUnavailable')}</p>}
        </div>
      </section>
    </div>
  );
}
