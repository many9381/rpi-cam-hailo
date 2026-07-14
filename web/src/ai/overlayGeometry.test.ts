import { describe, expect, it } from 'vitest';

import type { DetectionSnapshot } from '../api/types';
import {
  buildOverlayPrimitives,
  COCO_17_SKELETON,
  computeContainedImageRect,
} from './overlayGeometry';

const snapshot = (events: DetectionSnapshot['events']): DetectionSnapshot => ({ events });

const event = (
  cameraId: string,
  modelId: string,
  detections: DetectionSnapshot['events'][number]['detections'],
): DetectionSnapshot['events'][number] => ({
  camera_id: cameraId,
  model_id: modelId,
  model_kind: 'future_pose',
  result_state: 'ready',
  frame_sequence: 1,
  frame_timestamp_ns: 2,
  detections,
});

describe('buildOverlayPrimitives', () => {
  it('clamps normalized boxes and converts them to canvas pixels', () => {
    const result = buildOverlayPrimitives(snapshot([
      event('cam-a', 'objects', [{
        class_id: 0,
        label: 'person', confidence: 0.875,
        box: { x: -0.1, y: 0.25, width: 1.3, height: 0.9 },
        keypoints: [],
      }]),
    ]), 'cam-a', 1280, 720);

    expect(result.boxes).toEqual([{
      x: 0, y: 180, width: 1280, height: 540,
      label: 'person', confidence: 0.875, modelId: 'objects',
    }]);
  });

  it('maps normalized primitives into an offset contained-image rectangle', () => {
    const buildForRect = buildOverlayPrimitives as unknown as (
      value: DetectionSnapshot,
      cameraId: string,
      rect: { x: number; y: number; width: number; height: number },
    ) => ReturnType<typeof buildOverlayPrimitives>;
    const result = buildForRect(snapshot([
      event('cam-a', 'objects', [{
        class_id: 0,
        label: 'person', confidence: 0.75,
        box: { x: 0.1, y: 0.2, width: 0.5, height: 0.5 },
        keypoints: [
          { name: 'left_shoulder', x: 0.2, y: 0.3, confidence: 0.9 },
          { name: 'right_shoulder', x: 0.4, y: 0.3, confidence: 0.8 },
        ],
      }]),
    ]), 'cam-a', { x: 350, y: 0, width: 900, height: 900 });

    expect(result.boxes[0].x).toBeCloseTo(440);
    expect(result.boxes[0].y).toBeCloseTo(180);
    expect(result.boxes[0].width).toBeCloseTo(450);
    expect(result.boxes[0].height).toBeCloseTo(450);
    expect(result.skeleton[0]).toMatchObject({
      x1: 530, y1: 270, x2: 710, y2: 270,
    });
  });

  it('drops zero-area and non-finite boxes', () => {
    const result = buildOverlayPrimitives(snapshot([
      event('cam-a', 'objects', [
        { class_id: 0, label: 'zero', confidence: 1, box: { x: 0.5, y: 0.5, width: 0, height: 1 }, keypoints: [] },
        { class_id: 0, label: 'outside', confidence: 1, box: { x: 2, y: 0, width: 1, height: 1 }, keypoints: [] },
        { class_id: 0, label: 'nan', confidence: 1, box: { x: Number.NaN, y: 0, width: 1, height: 1 }, keypoints: [] },
      ]),
    ]), 'cam-a', 1280, 720);

    expect(result.boxes).toEqual([]);
  });

  it('filters by camera while combining results from multiple models', () => {
    const detection = (label: string) => ({
      class_id: 0, label, confidence: 0.5,
      box: { x: 0, y: 0, width: 0.25, height: 0.25 }, keypoints: [],
    });
    const result = buildOverlayPrimitives(snapshot([
      event('cam-a', 'model-one', [detection('one')]),
      event('cam-b', 'ignored', [detection('other-camera')]),
      event('cam-a', 'model-two', [detection('two')]),
    ]), 'cam-a', 1280, 720);

    expect(result.boxes.map(({ label, modelId }) => [label, modelId])).toEqual([
      ['one', 'model-one'], ['two', 'model-two'],
    ]);
  });

  it('keeps finite positive-confidence named keypoints and builds the COCO-17 skeleton', () => {
    const keypoints = [
      { name: 'left_shoulder', x: -0.2, y: 0.5, confidence: 0.9 },
      { name: 'right_shoulder', x: 0.75, y: 1.2, confidence: 0.8 },
      { name: 'left_elbow', x: 0.25, y: 0.75, confidence: 0 },
      { name: 'right_elbow', x: Number.POSITIVE_INFINITY, y: 0.4, confidence: 0.7 },
    ];
    const result = buildOverlayPrimitives(snapshot([
      event('cam-a', 'unknown-pose-model', [{
        class_id: 0,
        label: 'pose', confidence: 0.9,
        box: { x: 0, y: 0, width: 1, height: 1 }, keypoints,
      }]),
    ]), 'cam-a', 1280, 720);

    expect(result.keypoints).toEqual([
      { name: 'left_shoulder', x: 0, y: 360, confidence: 0.9 },
      { name: 'right_shoulder', x: 960, y: 720, confidence: 0.8 },
    ]);
    expect(result.skeleton).toEqual([{
      x1: 0, y1: 360, x2: 960, y2: 720,
      from: 'left_shoulder', to: 'right_shoulder',
    }]);
    expect(COCO_17_SKELETON).toContainEqual(['left_shoulder', 'right_shoulder']);
  });
});

describe('computeContainedImageRect', () => {
  it('returns the full stage for matching aspect ratios', () => {
    expect(computeContainedImageRect(1600, 900, 1280, 720)).toEqual({
      x: 0, y: 0, width: 1600, height: 900,
    });
  });

  it('centers a non-16:9 image inside the stage letterboxing', () => {
    expect(computeContainedImageRect(1600, 900, 800, 800)).toEqual({
      x: 350, y: 0, width: 900, height: 900,
    });
    expect(computeContainedImageRect(1600, 900, 2000, 1000)).toEqual({
      x: 0, y: 50, width: 1600, height: 800,
    });
  });

  it('returns a zero rect for invalid dimensions', () => {
    expect(computeContainedImageRect(0, 900, 800, 800)).toEqual({
      x: 0, y: 0, width: 0, height: 0,
    });
  });
});
