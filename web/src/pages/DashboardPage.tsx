import { RefreshCw } from 'lucide-react';
import { useCallback, useEffect } from 'react';

import { parseRestartAiResult } from '../api/contracts';
import { AiPanel } from '../components/AiPanel';
import { CameraPreview } from '../components/CameraPreview';
import { StatusPanel } from '../components/StatusPanel';
import { StreamPanel } from '../components/StreamPanel';
import type { CameraApiClient, DetectionSnapshot } from '../api/types';
import { useDetectionStream } from '../hooks/useDetectionStream';
import type { OperationalController } from '../hooks/useOperationalData';

interface DashboardPageProps {
  client: CameraApiClient;
  controller: OperationalController;
  view?: OperationalView;
}

export type OperationalView = 'dashboard' | 'cameras' | 'ai' | 'system';

const viewHeadings: Record<OperationalView, { title: string; subtitle: string }> = {
  dashboard: {
    title: 'Operational dashboard',
    subtitle: 'Camera, secure stream, and Hailo runtime status',
  },
  cameras: {
    title: 'Cameras',
    subtitle: 'Live preview and camera inventory',
  },
  ai: {
    title: 'AI inference',
    subtitle: 'Hailo model runners and current detections',
  },
  system: {
    title: 'System',
    subtitle: 'Device health and secure stream transport',
  },
};

export function DashboardPage({
  client,
  controller,
  view = 'dashboard',
}: DashboardPageProps) {
  const refresh = () => void controller.refresh().catch(() => undefined);
  const initialDetections: DetectionSnapshot = controller.data?.detections ?? { events: [] };
  const detectionStream = useDetectionStream(
    initialDetections,
    controller.data !== null,
  );

  useEffect(() => {
    if (controller.data !== null &&
        controller.data.detections !== detectionStream.snapshot) {
      controller.replaceDetections(detectionStream.snapshot);
    }
  }, [controller, detectionStream.snapshot]);

  const restartAi = useCallback(async () => {
    const result = await client.postJson(
      '/api/v1/ai/restart',
      {},
      parseRestartAiResult,
    );
    if (result.ai !== undefined) {
      controller.replaceAiStatus(result.ai);
      return;
    }
    await controller.refresh();
  }, [client, controller]);

  if (controller.data === null) {
    return (
      <section className="dashboard-page dashboard-state">
        {controller.state === 'loading'
          ? <p>Loading operational data...</p>
          : <><p role="alert">Operational data is unavailable.</p>
            <button type="button" onClick={refresh}>Retry</button></>}
      </section>
    );
  }

  const { data } = controller;
  const heading = viewHeadings[view];
  const showPreview = view === 'dashboard' || view === 'cameras' || view === 'ai';
  const showStatus = view === 'dashboard' || view === 'cameras' || view === 'system';
  const showStream = view === 'dashboard' || view === 'system';
  const showAi = view === 'dashboard' || view === 'ai';
  return (
    <div className="dashboard-page">
      <header className="dashboard-heading">
        <div>
          <h1>{heading.title}</h1>
          <p>{heading.subtitle}</p>
        </div>
        <button className="refresh-button" type="button"
          aria-label="Refresh operational data" title="Refresh operational data"
          onClick={refresh}>
          <RefreshCw size={17} aria-hidden="true" />
          Refresh
        </button>
      </header>
      {controller.state === 'stale' && (
        <p className="stale-notice" role="status">Showing the last available status.</p>
      )}
      {showPreview && (
        <CameraPreview cameras={data.cameras}
          selectedCameraId={controller.selectedCameraId}
          onSelectCamera={controller.selectCamera} snapshot={detectionStream.snapshot} />
      )}
      {showStatus && (
        <StatusPanel health={data.health} cameras={data.cameras}
          selectedCameraId={controller.selectedCameraId}
          onSelectCamera={controller.selectCamera} />
      )}
      {showStream && <StreamPanel stream={data.stream} />}
      {showAi && (
        <AiPanel ai={data.ai} detections={detectionStream.snapshot}
          streamStatus={detectionStream.status} onRestart={restartAi} />
      )}
    </div>
  );
}
