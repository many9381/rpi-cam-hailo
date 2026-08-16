import { RefreshCw } from 'lucide-react';
import { useCallback, useEffect } from 'react';

import { parseRestartAiResult, parseRuntimeRestartResult } from '../api/contracts';
import { AiPanel } from '../components/AiPanel';
import { CameraPreview } from '../components/CameraPreview';
import { StatusPanel } from '../components/StatusPanel';
import { StreamPanel } from '../components/StreamPanel';
import type { CameraApiClient, DetectionSnapshot } from '../api/types';
import { AuditRecordsPanel } from '../features/audit/AuditRecordsPanel';
import type { AuditStatusController } from '../features/audit/useAuditStatus';
import { SystemProtectionPanel } from '../features/protection/SystemProtectionPanel';
import type { SystemProtectionController } from '../features/protection/useSystemProtection';
import { AiSettingsPanel } from '../features/settings/AiSettingsPanel';
import { CameraSettingsPanel } from '../features/settings/CameraSettingsPanel';
import { SettingsActionBar } from '../features/settings/SettingsActionBar';
import type { RuntimeSettingsController } from '../features/settings/useRuntimeSettings';
import { useDetectionStream } from '../hooks/useDetectionStream';
import type { OperationalController } from '../hooks/useOperationalData';

interface DashboardPageProps {
  client: CameraApiClient;
  controller: OperationalController;
  runtimeSettings?: RuntimeSettingsController;
  auditStatus?: AuditStatusController;
  protection?: SystemProtectionController;
  auditFragment?: string;
  view?: OperationalView;
}

export type OperationalView = 'dashboard' | 'cameras' | 'ai' | 'system';

const viewHeadings: Record<OperationalView, { title: string; subtitle: string }> = {
  dashboard: {
    title: 'Dashboard',
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
  runtimeSettings,
  auditStatus,
  protection,
  auditFragment,
  view = 'dashboard',
}: DashboardPageProps) {
  const refresh = () => {
    void controller.refresh().catch(() => undefined);
    if (runtimeSettings !== undefined) {
      void runtimeSettings.refresh().catch(() => undefined);
    }
    if (auditStatus !== undefined) {
      void auditStatus.refresh().catch(() => undefined);
    }
    if (protection !== undefined) {
      void protection.refresh().catch(() => undefined);
    }
  };
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

  const restartRuntime = useCallback(async () => {
    await client.postJson(
      '/api/v1/runtime/restart',
      {},
      parseRuntimeRestartResult,
    );
    await controller.refresh();
  }, [client, controller]);

  const heading = viewHeadings[view];
  const operationalState = controller.state === 'loading'
    ? <p>Loading operational data...</p>
    : <><p role="alert">Operational data is unavailable.</p>
      <button type="button" onClick={refresh}>Retry</button></>;
  if (controller.data === null && view !== 'system') {
    return (
      <section className="dashboard-page dashboard-state">
        {operationalState}
      </section>
    );
  }

  const data = controller.data;
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
      {data === null && (
        <section className="dashboard-state">{operationalState}</section>
      )}
      {data !== null && showPreview && (
        <CameraPreview cameras={data.cameras}
          selectedCameraId={controller.selectedCameraId}
          onSelectCamera={controller.selectCamera} snapshot={detectionStream.snapshot} />
      )}
      {data !== null && showStatus && (
        <StatusPanel health={data.health} cameras={data.cameras}
          selectedCameraId={controller.selectedCameraId}
          onSelectCamera={controller.selectCamera}
          onRestartRuntime={restartRuntime} />
      )}
      {data !== null && showStream && <StreamPanel stream={data.stream} />}
      {data !== null && showAi && (
        <AiPanel ai={data.ai} detections={detectionStream.snapshot}
          streamStatus={detectionStream.status} onRestart={restartAi} />
      )}
      {view === 'system' && protection !== undefined && (
        <SystemProtectionPanel controller={protection} />
      )}
      {view === 'system' && (
        <AuditRecordsPanel client={client} auditStatus={auditStatus}
          routeFragment={auditFragment} />
      )}
      {data !== null && view === 'cameras' && runtimeSettings !== undefined && (
        <>
          <CameraSettingsPanel controller={runtimeSettings} />
          <SettingsActionBar controller={runtimeSettings}
            onApplySettled={() => void controller.refresh().catch(() => undefined)} />
        </>
      )}
      {data !== null && view === 'ai' && runtimeSettings !== undefined && (
        <>
          <AiSettingsPanel controller={runtimeSettings} />
          <SettingsActionBar controller={runtimeSettings}
            onApplySettled={() => void controller.refresh().catch(() => undefined)} />
        </>
      )}
    </div>
  );
}
