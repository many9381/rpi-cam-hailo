import type { DetectionSnapshot } from '../api/types';

export const COCO_17_SKELETON = [
  ['nose', 'left_eye'],
  ['nose', 'right_eye'],
  ['left_eye', 'left_ear'],
  ['right_eye', 'right_ear'],
  ['left_ear', 'left_shoulder'],
  ['right_ear', 'right_shoulder'],
  ['left_shoulder', 'right_shoulder'],
  ['left_shoulder', 'left_elbow'],
  ['left_elbow', 'left_wrist'],
  ['right_shoulder', 'right_elbow'],
  ['right_elbow', 'right_wrist'],
  ['left_shoulder', 'left_hip'],
  ['right_shoulder', 'right_hip'],
  ['left_hip', 'right_hip'],
  ['left_hip', 'left_knee'],
  ['left_knee', 'left_ankle'],
  ['right_hip', 'right_knee'],
  ['right_knee', 'right_ankle'],
] as const;

export interface OverlayBox {
  x: number;
  y: number;
  width: number;
  height: number;
  label: string;
  confidence: number;
  modelId: string;
}

export interface OverlayKeypoint {
  name: string;
  x: number;
  y: number;
  confidence: number;
}

export interface OverlaySkeletonLine {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  from: string;
  to: string;
}

export interface OverlayPrimitives {
  boxes: OverlayBox[];
  keypoints: OverlayKeypoint[];
  skeleton: OverlaySkeletonLine[];
}

export interface ImageRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

const clamp = (value: number): number => Math.min(1, Math.max(0, value));

export function buildOverlayPrimitives(
  snapshot: DetectionSnapshot,
  cameraId: string,
  imageRectOrWidth: ImageRect | number,
  imageHeight?: number,
): OverlayPrimitives {
  const primitives: OverlayPrimitives = { boxes: [], keypoints: [], skeleton: [] };
  const imageRect = typeof imageRectOrWidth === 'number'
    ? { x: 0, y: 0, width: imageRectOrWidth, height: imageHeight ?? 0 }
    : imageRectOrWidth;
  if (![imageRect.x, imageRect.y, imageRect.width, imageRect.height].every(Number.isFinite) ||
      imageRect.width <= 0 || imageRect.height <= 0) {
    return primitives;
  }

  for (const result of snapshot.events) {
    if (result.camera_id !== cameraId) {
      continue;
    }
    for (const detection of result.detections) {
      const { box } = detection;
      if ([box.x, box.y, box.width, box.height].every(Number.isFinite)) {
        const left = clamp(box.x);
        const top = clamp(box.y);
        const right = clamp(box.x + box.width);
        const bottom = clamp(box.y + box.height);
        if (right > left && bottom > top) {
          primitives.boxes.push({
            x: imageRect.x + left * imageRect.width,
            y: imageRect.y + top * imageRect.height,
            width: (right - left) * imageRect.width,
            height: (bottom - top) * imageRect.height,
            label: detection.label,
            confidence: detection.confidence,
            modelId: result.model_id,
          });
        }
      }

      const pointsByName = new Map<string, OverlayKeypoint>();
      for (const point of detection.keypoints) {
        if (point.name.length === 0 || !Number.isFinite(point.x) ||
            !Number.isFinite(point.y) || !Number.isFinite(point.confidence) ||
            point.confidence <= 0) {
          continue;
        }
        const primitive = {
          name: point.name,
          x: imageRect.x + clamp(point.x) * imageRect.width,
          y: imageRect.y + clamp(point.y) * imageRect.height,
          confidence: point.confidence,
        };
        primitives.keypoints.push(primitive);
        pointsByName.set(point.name, primitive);
      }

      for (const [from, to] of COCO_17_SKELETON) {
        const start = pointsByName.get(from);
        const end = pointsByName.get(to);
        if (start !== undefined && end !== undefined) {
          primitives.skeleton.push({
            x1: start.x,
            y1: start.y,
            x2: end.x,
            y2: end.y,
            from,
            to,
          });
        }
      }
    }
  }
  return primitives;
}

export function computeContainedImageRect(
  stageWidth: number,
  stageHeight: number,
  naturalWidth: number,
  naturalHeight: number,
): ImageRect {
  if (![stageWidth, stageHeight, naturalWidth, naturalHeight].every(Number.isFinite) ||
      stageWidth <= 0 || stageHeight <= 0 || naturalWidth <= 0 || naturalHeight <= 0) {
    return { x: 0, y: 0, width: 0, height: 0 };
  }
  const scale = Math.min(stageWidth / naturalWidth, stageHeight / naturalHeight);
  const width = naturalWidth * scale;
  const height = naturalHeight * scale;
  return {
    x: (stageWidth - width) / 2,
    y: (stageHeight - height) / 2,
    width,
    height,
  };
}
