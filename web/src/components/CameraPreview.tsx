import { RefreshCw } from 'lucide-react';
import { useState } from 'react';

import type { CameraApiClient, CameraStatus, DetectionSnapshot } from '../api/types';
import { useSnapshot } from '../hooks/useSnapshot';
import { DetectionOverlay } from './DetectionOverlay';
import { IconButton } from './IconButton';

interface CameraPreviewProps {
  client: CameraApiClient;
  cameras: CameraStatus[];
  selectedCameraId: string;
  onSelectCamera(id: string): void;
  snapshot: DetectionSnapshot;
}

interface ImageDimensions {
  width: number;
  height: number;
  objectUrl: string;
}

export function CameraPreview({
  client,
  cameras,
  selectedCameraId,
  onSelectCamera,
  snapshot,
}: CameraPreviewProps) {
  const selectedCamera = cameras.find(({ id }) => id === selectedCameraId);
  const snapshotCameraId = selectedCamera?.snapshot_available === true
    ? selectedCameraId : '';
  const resource = useSnapshot(client, snapshotCameraId);
  const [imageSize, setImageSize] = useState<ImageDimensions | null>(null);
  const [decodeErrorUrl, setDecodeErrorUrl] = useState<string | null>(null);

  const hasReadyResource = resource.state === 'ready' && resource.objectUrl !== null;
  const objectUrl = hasReadyResource ? resource.objectUrl : null;
  const hasDecodeError = objectUrl !== null && decodeErrorUrl === objectUrl;
  const currentImageSize = objectUrl !== null && imageSize?.objectUrl === objectUrl
    ? imageSize : null;
  const refresh = () => void resource.refresh().catch(() => undefined);
  const hasSnapshot = objectUrl !== null && !hasDecodeError;

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
          <IconButton label="Refresh snapshot" onClick={refresh}
            disabled={snapshotCameraId.length === 0}>
            <RefreshCw size={17} aria-hidden="true" />
          </IconButton>
        </div>
      </div>
      <div className="camera-stage" aria-busy={resource.state === 'loading'}>
        {hasSnapshot && (
          <img key={objectUrl} src={objectUrl} alt={`${selectedCameraId} snapshot`}
            onLoad={(event) => setImageSize({
              objectUrl,
              width: event.currentTarget.naturalWidth,
              height: event.currentTarget.naturalHeight,
            })}
            onError={() => setDecodeErrorUrl(objectUrl)} />
        )}
        {hasSnapshot && currentImageSize !== null && (
            <DetectionOverlay snapshot={snapshot} cameraId={selectedCameraId}
              imageWidth={currentImageSize.width}
              imageHeight={currentImageSize.height} />
          )}
        {selectedCamera === undefined && (
          <p className="camera-stage-state">No camera selected</p>
        )}
        {selectedCamera !== undefined && !selectedCamera.snapshot_available && (
          <p className="camera-stage-state">Snapshot unavailable for this camera</p>
        )}
        {snapshotCameraId.length > 0 && resource.state === 'loading' && (
          <p className="camera-stage-state">Loading snapshot...</p>
        )}
        {snapshotCameraId.length > 0 &&
          (resource.state === 'unavailable' || hasDecodeError) && (
          <p className="camera-stage-state">Snapshot unavailable</p>
        )}
      </div>
    </section>
  );
}
