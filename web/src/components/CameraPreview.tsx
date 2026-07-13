import { RefreshCw } from 'lucide-react';
import { useState } from 'react';

import type { CameraStatus, DetectionSnapshot } from '../api/types';
import { useMjpegPreview } from '../hooks/useMjpegPreview';
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
  streamUrl: string;
}

export function CameraPreview({
  cameras,
  selectedCameraId,
  onSelectCamera,
  snapshot,
}: CameraPreviewProps) {
  const selectedCamera = cameras.find(({ id }) => id === selectedCameraId);
  const previewCameraId = selectedCamera !== undefined ? selectedCameraId : '';
  const preview = useMjpegPreview(previewCameraId);
  const [imageSize, setImageSize] = useState<ImageDimensions | null>(null);
  const [loadedUrl, setLoadedUrl] = useState('');
  const currentImageSize = imageSize?.streamUrl === preview.streamUrl
    ? imageSize : null;
  const hasStream = preview.streamUrl.length > 0;
  const stageStatus = preview.state === 'connecting'
    ? 'Connecting preview...'
    : preview.state === 'reconnecting'
      ? 'Preview reconnecting...'
      : preview.state === 'unavailable'
        ? selectedCameraId.length > 0 ? 'Preview unavailable.' : 'No camera selected.'
        : '';

  return (
    <section className="operational-section" aria-labelledby="preview-heading">
      <div className="section-heading camera-preview-heading">
        <div>
          <h2 id="preview-heading">Camera preview</h2>
          <p>{selectedCameraId || 'No camera selected'}</p>
        </div>
        <div className="camera-preview-controls">
          <label htmlFor="preview-camera">Camera</label>
          <select id="preview-camera" value={selectedCameraId}
            onChange={(event) => onSelectCamera(event.target.value)}
            disabled={cameras.length === 0}>
            {cameras.length === 0 && <option value="">No cameras</option>}
            {cameras.map(({ id }) => <option key={id} value={id}>{id}</option>)}
          </select>
          <IconButton label="Reconnect preview" onClick={preview.reconnect}
            disabled={previewCameraId.length === 0}>
            <RefreshCw size={17} aria-hidden="true" />
          </IconButton>
        </div>
      </div>
      <div className="camera-stage" aria-busy={preview.state !== 'live' && preview.state !== 'unavailable'}>
        {hasStream && (
          <img key={preview.streamUrl} src={preview.streamUrl}
            className={`camera-preview-image${loadedUrl === preview.streamUrl ? ' is-loaded' : ''}`}
            alt={`${selectedCameraId} camera preview`}
            onLoad={(event) => {
              if (!preview.onLoad(preview.streamUrl)) {
                return;
              }
              setImageSize({
                streamUrl: preview.streamUrl,
                width: event.currentTarget.naturalWidth,
                height: event.currentTarget.naturalHeight,
              });
              setLoadedUrl(preview.streamUrl);
            }}
            onError={() => {
              if (!preview.onError(preview.streamUrl)) {
                return;
              }
              setLoadedUrl('');
              setImageSize(null);
            }} />
        )}
        {hasStream && currentImageSize !== null && (
            <DetectionOverlay snapshot={snapshot} cameraId={selectedCameraId}
              imageWidth={currentImageSize.width}
              imageHeight={currentImageSize.height} />
          )}
        <p className="camera-stage-state" role="status">{stageStatus}</p>
      </div>
    </section>
  );
}
