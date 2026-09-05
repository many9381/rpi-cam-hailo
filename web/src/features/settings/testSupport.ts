import { vi } from 'vitest';

import type {
  LastApply,
  RuntimeSettings,
  RuntimeSettingsSnapshot,
  RuntimeSettingsState,
} from './contracts';
import type { RuntimeSettingsController } from './useRuntimeSettings';

export const makeSettings = (
  profileId = 'imx708-1080p50',
  bitrateKbps = 6_000,
): RuntimeSettings => ({
  camera: { profile_id: profileId, bitrate_kbps: bitrateKbps, gop: 25 },
  sub_stream: {
    enabled: false, width: 640, height: 360, fps: 15, bitrate_kbps: 1_000,
  },
  osd: { enabled: false, items: [] },
  models: [
    { id: 'objects', enabled: true, confidence_threshold: 0.4 },
    { id: 'pose', enabled: false, confidence_threshold: 0.5 },
  ],
});

export const makeSettingsSnapshot = ({
  revision = 1,
  state,
  pending = null,
  lastApply = { status: 'never', code: '', restored: false },
}: {
  revision?: number;
  state?: RuntimeSettingsState;
  pending?: RuntimeSettings | null;
  lastApply?: LastApply;
} = {}): RuntimeSettingsSnapshot => ({
  schema_version: 1,
  revision,
  state: state ?? (pending === null ? 'clean' : 'pending'),
  capabilities: {
    camera_profiles: [
      { id: 'imx708-1080p50', width: 1920, height: 1080, fps: 50,
        label: '1080p / 50 fps' },
      { id: 'imx708-1080p30', width: 1920, height: 1080, fps: 30,
        label: '1080p / 30 fps' },
      { id: 'imx708-720p50', width: 1280, height: 720, fps: 50,
        label: '720p / 50 fps' },
    ],
    bitrate_kbps: { minimum: 500, maximum: 20_000 },
    gop: { minimum: 1, maximum: 300 },
    models: [
      { id: 'objects', kind: 'object_detection', input_width: 640,
        input_height: 640, input_format: 'RGB', letterbox: true,
        labels: 'coco80' },
      { id: 'pose', kind: 'pose', input_width: 640, input_height: 640,
        input_format: 'RGB', letterbox: true, labels: 'pose17' },
    ],
  },
  active: makeSettings(),
  pending,
  last_apply: lastApply,
});

export const makeSettingsController = (
  overrides: Partial<RuntimeSettingsController> = {},
): RuntimeSettingsController => {
  const snapshot = overrides.snapshot === undefined
    ? makeSettingsSnapshot()
    : overrides.snapshot;
  return {
    status: 'ready',
    snapshot,
    draft: snapshot === null ? null : (snapshot.pending ?? snapshot.active),
    dirty: false,
    error: null,
    updateCamera: vi.fn(),
    updateSubStream: vi.fn(),
    updateOsd: vi.fn(),
    updateModel: vi.fn(),
    save: vi.fn(async () => undefined),
    apply: vi.fn(async () => undefined),
    discard: vi.fn(async () => undefined),
    refresh: vi.fn(async () => undefined),
    ...overrides,
  };
};
