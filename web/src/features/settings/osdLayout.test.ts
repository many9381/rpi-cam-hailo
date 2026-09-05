import { describe, expect, it } from 'vitest';

import type { OsdItem } from './contracts';
import {
  OSD_FONT_RATIO,
  OSD_INSET_RATIO,
  formatOsdTimestamp,
  resolveOsdItemText,
} from './osdLayout';

const item = (overrides: Partial<OsdItem>): OsdItem => ({
  type: 'custom_text', text: '', position: 'top_left', ...overrides,
});

describe('osdLayout', () => {
  it('publishes the shared preview/burn-in layout ratios', () => {
    expect(OSD_FONT_RATIO).toBe(0.035);
    expect(OSD_INSET_RATIO).toBe(0.02);
  });

  it('formats timestamps as zero-padded local YYYY-MM-DD HH:MM:SS', () => {
    expect(formatOsdTimestamp(new Date(2026, 8, 5, 14, 30, 7)))
      .toBe('2026-09-05 14:30:07');
    expect(formatOsdTimestamp(new Date(2026, 0, 1, 0, 0, 0)))
      .toBe('2026-01-01 00:00:00');
  });

  it('resolves each item type to its on-screen text', () => {
    const now = new Date(2026, 8, 5, 14, 30, 7);
    expect(resolveOsdItemText(item({ type: 'timestamp', text: 'ignored' }), 'cam-a', now))
      .toBe('2026-09-05 14:30:07');
    expect(resolveOsdItemText(item({ type: 'camera_name', text: 'ignored' }), 'cam-a', now))
      .toBe('cam-a');
    expect(resolveOsdItemText(item({ type: 'custom_text', text: 'Front door' }), 'cam-a', now))
      .toBe('Front door');
  });
});
