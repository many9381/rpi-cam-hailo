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
import { CameraSettingsPanel, type CameraSettingsSection } from '../features/settings/CameraSettingsPanel';
import { SettingsActionBar } from '../features/settings/SettingsActionBar';
import type { RuntimeSettingsController } from '../features/settings/useRuntimeSettings';
import { useDetectionStream } from '../hooks/useDetectionStream';
import type { OperationalController } from '../hooks/useOperationalData';
import { useTranslation } from '../i18n/LanguageContext';

interface DashboardPageProps {
  client: CameraApiClient;
  controller: OperationalController;
  runtimeSettings?: RuntimeSettingsController;
  auditStatus?: AuditStatusController;
  protection?: SystemProtectionController;
  auditFragment?: string;
  view?: OperationalView;
}

export type OperationalView =
  | 'dashboard'
  | 'cameras'
  | 'cameras-substream'
  | 'cameras-osd'
  | 'ai'
  | 'system';

const viewHeadings: Record<OperationalView, { titleKey: string; subtitleKey: string }> = {
  dashboard: {
    titleKey: 'dashboard.dashboardTitle',
    subtitleKey: 'dashboard.dashboardSubtitle',
  },
  cameras: {
    titleKey: 'dashboard.camerasTitle',
    subtitleKey: 'dashboard.camerasSubtitle',
  },
  'cameras-substream': {
    titleKey: 'dashboard.camerasTitle',
    subtitleKey: 'dashboard.camerasSubtitle',
  },
  'cameras-osd': {
    titleKey: 'dashboard.camerasTitle',
    subtitleKey: 'dashboard.camerasSubtitle',
  },
  ai: {
    titleKey: 'dashboard.aiTitle',
    subtitleKey: 'dashboard.aiSubtitle',
  },
  system: {
    titleKey: 'dashboard.systemTitle',
    subtitleKey: 'dashboard.systemSubtitle',
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
  const { t } = useTranslation();
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
    ? <p>{t('dashboard.loadingOperationalData')}</p>
    : <><p role="alert">{t('dashboard.operationalDataUnavailable')}</p>
      <button type="button" onClick={refresh}>{t('common.retry')}</button></>;
  if (controller.data === null && view !== 'system') {
    return (
      <section className="dashboard-page dashboard-state">
        {operationalState}
      </section>
    );
  }

  const data = controller.data;
  const cameraSection: CameraSettingsSection | null =
    view === 'cameras' ? 'camera'
      : view === 'cameras-substream' ? 'sub_stream'
        : view === 'cameras-osd' ? 'osd'
          : null;
  const isCameraView = cameraSection !== null;
  const showPreview = view === 'dashboard' || isCameraView || view === 'ai';
  const showStatus = view === 'dashboard' || isCameraView || view === 'system';
  // The OSD editor previews the unsaved draft so edits show up as they are
  // made; every other preview mirrors what the firmware currently applies.
  const previewOsd = runtimeSettings === undefined
    ? undefined
    : view === 'cameras-osd'
      ? runtimeSettings.draft?.osd ?? runtimeSettings.snapshot?.active.osd
      : runtimeSettings.snapshot?.active.osd;
  const showStream = view === 'dashboard' || view === 'system';
  const showAi = view === 'dashboard' || view === 'ai';
  return (
    <div className="dashboard-page">
      <header className="dashboard-heading">
        <div>
          <h1>{t(heading.titleKey)}</h1>
          <p>{t(heading.subtitleKey)}</p>
        </div>
        <button className="refresh-button" type="button"
          aria-label={t('dashboard.refreshOperationalData')} title={t('dashboard.refreshOperationalData')}
          onClick={refresh}>
          <RefreshCw size={17} aria-hidden="true" />
          {t('dashboard.refresh')}
        </button>
      </header>
      {controller.state === 'stale' && (
        <p className="stale-notice" role="status">{t('dashboard.staleNotice')}</p>
      )}
      {data === null && (
        <section className="dashboard-state">{operationalState}</section>
      )}
      {data !== null && showPreview && (
        <CameraPreview cameras={data.cameras}
          selectedCameraId={controller.selectedCameraId}
          onSelectCamera={controller.selectCamera} snapshot={detectionStream.snapshot}
          osd={previewOsd} />
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
      {data !== null && cameraSection !== null && runtimeSettings !== undefined && (
        <>
          <CameraSettingsPanel controller={runtimeSettings} section={cameraSection} />
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
