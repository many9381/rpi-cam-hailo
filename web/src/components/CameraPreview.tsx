import { RefreshCw } from 'lucide-react';
import { useEffect, useState } from 'react';

import type { CameraStatus, DetectionSnapshot } from '../api/types';
import { useLivePreview } from '../hooks/useLivePreview';
import { useTranslation } from '../i18n/LanguageContext';
import { DetectionOverlay } from './DetectionOverlay';
import { IconButton } from './IconButton';

interface CameraPreviewProps {
  cameras: CameraStatus[];
  selectedCameraId: string;
  onSelectCamera(id: string): void;
  snapshot: DetectionSnapshot;
}

interface ImageDimensions {
  width: number;
  height: number;
  generation: number;
}

export function CameraPreview({
  cameras,
  selectedCameraId,
  onSelectCamera,
  snapshot,
}: CameraPreviewProps) {
  const { t } = useTranslation();
  const selectedCamera = cameras.find(({ id }) => id === selectedCameraId);
  const previewCameraId = selectedCamera !== undefined ? selectedCameraId : '';
  const preview = useLivePreview(previewCameraId);
  const [imageSize, setImageSize] = useState<ImageDimensions | null>(null);
  const currentImageSize = imageSize?.generation === preview.generation
    ? imageSize : null;
  useEffect(() => setImageSize(null), [preview.generation]);
  const stageStatus = preview.state === 'connecting'
    ? t('camera.connectingPreview')
    : preview.state === 'reconnecting'
      ? t('camera.reconnectingPreview')
      : preview.state === 'unavailable'
        ? selectedCameraId.length > 0 ? t('camera.previewUnavailable') : t('camera.noCameraSelectedStatus')
        : '';

  return (
    <section className="operational-section" aria-labelledby="preview-heading">
      <div className="section-heading camera-preview-heading">
        <div>
          <h2 id="preview-heading">{t('camera.title')}</h2>
          <p>{selectedCameraId || t('camera.noCameraSelected')}</p>
        </div>
        <div className="camera-preview-controls">
          <label htmlFor="preview-camera">{t('camera.cameraLabel')}</label>
          <select id="preview-camera" value={selectedCameraId}
            onChange={(event) => onSelectCamera(event.target.value)}
            disabled={cameras.length === 0}>
            {cameras.length === 0 && <option value="">{t('camera.noCamerasOption')}</option>}
            {cameras.map(({ id }) => <option key={id} value={id}>{id}</option>)}
          </select>
          <IconButton label={t('camera.reconnectPreview')} onClick={preview.reconnect}
            disabled={previewCameraId.length === 0}>
            <RefreshCw size={17} aria-hidden="true" />
          </IconButton>
        </div>
      </div>
      <div className="camera-stage" aria-busy={preview.state !== 'live' && preview.state !== 'unavailable'}>
        {previewCameraId.length > 0 && (
          <video ref={preview.videoRef} autoPlay muted playsInline
            className={`camera-preview-video${preview.state === 'live' ? ' is-live' : ''}`}
            aria-label={t('camera.videoLabel', { id: selectedCameraId })}
            onLoadedMetadata={(event) => {
              if (event.currentTarget.videoWidth === 0 ||
                  event.currentTarget.videoHeight === 0) {
                return;
              }
              setImageSize({
                generation: preview.generation,
                width: event.currentTarget.videoWidth,
                height: event.currentTarget.videoHeight,
              });
            }} />
        )}
        {preview.state === 'live' && currentImageSize !== null && (
            <DetectionOverlay snapshot={snapshot} cameraId={selectedCameraId}
              imageWidth={currentImageSize.width}
              imageHeight={currentImageSize.height} />
          )}
        <p className="camera-stage-state" role="status">{stageStatus}</p>
      </div>
    </section>
  );
}
