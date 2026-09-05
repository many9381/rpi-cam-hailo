import type { OsdItem } from './contracts';

// Shared OSD layout spec. The web preview overlay (OsdOverlay) renders with
// these values, and the firmware burn-in renderer must mirror them so what the
// operator sees while editing is what gets encoded into the video.

// Text height as a fraction of the frame height.
export const OSD_FONT_RATIO = 0.035;
// Corner inset (both axes) as a fraction of the frame height.
export const OSD_INSET_RATIO = 0.02;

const pad2 = (value: number): string => String(value).padStart(2, '0');

// Local time, zero-padded: YYYY-MM-DD HH:MM:SS.
export function formatOsdTimestamp(date: Date): string {
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}` +
    ` ${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
}

export function resolveOsdItemText(item: OsdItem, cameraId: string, now: Date): string {
  switch (item.type) {
    case 'timestamp':
      return formatOsdTimestamp(now);
    case 'camera_name':
      return cameraId;
    case 'custom_text':
      return item.text;
  }
}
