import { useEffect, useLayoutEffect, useRef, useState } from 'react';

import { buildOverlayPrimitives, computeContainedImageRect } from '../ai/overlayGeometry';
import type { DetectionSnapshot } from '../api/types';

interface DetectionOverlayProps {
  snapshot: DetectionSnapshot;
  cameraId: string;
  imageWidth: number;
  imageHeight: number;
}

interface CanvasSize {
  width: number;
  height: number;
}

export function DetectionOverlay({
  snapshot,
  cameraId,
  imageWidth,
  imageHeight,
}: DetectionOverlayProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [size, setSize] = useState<CanvasSize>({ width: 0, height: 0 });

  useLayoutEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null) {
      return;
    }
    const updateSize = (width: number, height: number) => {
      setSize((current) => current.width === width && current.height === height
        ? current : { width, height });
    };
    if (typeof ResizeObserver === 'undefined') {
      const rect = canvas.getBoundingClientRect();
      updateSize(rect.width, rect.height);
      return;
    }
    const observer = new ResizeObserver(([entry]) => {
      if (entry !== undefined) {
        updateSize(entry.contentRect.width, entry.contentRect.height);
      }
    });
    observer.observe(canvas);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (canvas === null || size.width <= 0 || size.height <= 0) {
      return;
    }
    const context = canvas.getContext('2d');
    if (context === null) {
      return;
    }
    const dpr = Math.max(1, window.devicePixelRatio || 1);
    canvas.width = Math.round(size.width * dpr);
    canvas.height = Math.round(size.height * dpr);
    context.setTransform(1, 0, 0, 1, 0, 0);
    context.clearRect(0, 0, canvas.width, canvas.height);
    context.scale(dpr, dpr);

    const imageRect = computeContainedImageRect(
      size.width, size.height, imageWidth, imageHeight);
    const primitives = buildOverlayPrimitives(snapshot, cameraId, imageRect);
    context.lineWidth = 2;
    context.strokeStyle = '#43e0d0';
    for (const line of primitives.skeleton) {
      context.beginPath();
      context.moveTo(line.x1, line.y1);
      context.lineTo(line.x2, line.y2);
      context.stroke();
    }

    context.font = '12px system-ui, sans-serif';
    context.textBaseline = 'top';
    for (const box of primitives.boxes) {
      context.strokeStyle = '#38e2d1';
      context.strokeRect(box.x, box.y, box.width, box.height);
      const label = `${box.label} ${Math.round(box.confidence * 100)}%`;
      const labelX = box.x + 4;
      const labelY = box.y + 4;
      context.fillStyle = 'rgb(10 24 27 / 82%)';
      context.fillRect(labelX - 3, labelY - 2, Math.max(52, label.length * 7), 18);
      context.fillStyle = '#ffffff';
      context.fillText(label, labelX, labelY);
    }

    context.fillStyle = '#ffd166';
    for (const point of primitives.keypoints) {
      context.beginPath();
      context.arc(point.x, point.y, 3, 0, Math.PI * 2);
      context.fill();
    }
  }, [cameraId, imageHeight, imageWidth, size, snapshot]);

  return <canvas ref={canvasRef} className="detection-overlay" aria-hidden="true" />;
}
