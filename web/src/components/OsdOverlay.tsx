import { useEffect, useLayoutEffect, useRef, useState } from 'react';

import { computeContainedImageRect, type ImageRect } from '../ai/overlayGeometry';
import { OSD_POSITIONS, type OsdRuntimeSettings } from '../features/settings/contracts';
import {
  OSD_FONT_RATIO,
  OSD_INSET_RATIO,
  resolveOsdItemText,
} from '../features/settings/osdLayout';

interface OsdOverlayProps {
  osd: OsdRuntimeSettings;
  cameraId: string;
  // Natural frame size from the video element. When unknown the overlay
  // anchors to the whole stage instead of the letterboxed video rect.
  imageWidth?: number;
  imageHeight?: number;
}

interface StageSize {
  width: number;
  height: number;
}

// Inline style lengths rounded to 1/100 px so float noise never reaches the DOM.
const px = (value: number): string => `${Math.round(value * 100) / 100}px`;

// Preview-side mirror of the OSD burn-in: anchors items to the four corners of
// the video frame using the shared osdLayout ratios so the on-screen result
// matches what the firmware encodes once the settings are applied.
export function OsdOverlay({ osd, cameraId, imageWidth, imageHeight }: OsdOverlayProps) {
  const rootRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState<StageSize>({ width: 0, height: 0 });
  const [now, setNow] = useState(() => new Date());
  const visible = osd.enabled && osd.items.length > 0;
  const hasTimestamp = visible && osd.items.some((item) => item.type === 'timestamp');

  useLayoutEffect(() => {
    const root = rootRef.current;
    if (root === null) {
      return;
    }
    const updateSize = (width: number, height: number) => {
      setSize((current) => current.width === width && current.height === height
        ? current : { width, height });
    };
    if (typeof ResizeObserver === 'undefined') {
      const rect = root.getBoundingClientRect();
      updateSize(rect.width, rect.height);
      return;
    }
    const observer = new ResizeObserver(([entry]) => {
      if (entry !== undefined) {
        updateSize(entry.contentRect.width, entry.contentRect.height);
      }
    });
    observer.observe(root);
    return () => observer.disconnect();
  }, [visible]);

  useEffect(() => {
    if (!hasTimestamp) {
      return;
    }
    setNow(new Date());
    const timer = window.setInterval(() => setNow(new Date()), 1_000);
    return () => window.clearInterval(timer);
  }, [hasTimestamp]);

  if (!visible) {
    return null;
  }

  const frame: ImageRect = imageWidth !== undefined && imageHeight !== undefined
    ? computeContainedImageRect(size.width, size.height, imageWidth, imageHeight)
    : { x: 0, y: 0, width: size.width, height: size.height };

  return (
    <div ref={rootRef} className="osd-overlay" aria-hidden="true">
      <div
        className="osd-frame"
        style={{
          left: px(frame.x),
          top: px(frame.y),
          width: px(frame.width),
          height: px(frame.height),
          fontSize: px(frame.height * OSD_FONT_RATIO),
          padding: px(frame.height * OSD_INSET_RATIO),
        }}
      >
        {OSD_POSITIONS.map((position) => {
          const items = osd.items.filter((item) => item.position === position);
          if (items.length === 0) {
            return null;
          }
          return (
            <div key={position} className={`osd-corner osd-corner-${position}`}>
              {items.map((item, index) => (
                <span key={`${item.type}-${index}`} className="osd-item">
                  {resolveOsdItemText(item, cameraId, now)}
                </span>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
