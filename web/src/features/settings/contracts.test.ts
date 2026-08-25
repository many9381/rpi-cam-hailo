import { describe, expect, it } from 'vitest';

import {
  parseRuntimeSettingsApplyResponse,
  parseRuntimeSettingsSnapshot,
} from './contracts';

const makeSnapshot = () => ({
  schema_version: 1,
  revision: 7,
  state: 'pending',
  capabilities: {
    camera_profiles: [
      {
        id: 'imx708-1080p50',
        width: 1920,
        height: 1080,
        fps: 50,
        label: '1080p / 50 fps',
      },
      {
        id: 'imx708-720p50',
        width: 1280,
        height: 720,
        fps: 50,
        label: '720p / 50 fps',
      },
    ],
    bitrate_kbps: { minimum: 500, maximum: 20_000 },
    gop: { minimum: 1, maximum: 300 },
    models: [
      {
        id: 'objects',
        kind: 'object_detection',
        input_width: 640,
        input_height: 640,
        input_format: 'rgb',
        letterbox: true,
        labels: 'coco80',
      },
      {
        id: 'pose',
        kind: 'pose',
        input_width: 640,
        input_height: 640,
        input_format: 'rgb',
        letterbox: true,
        labels: 'pose17',
      },
    ],
  },
  active: {
    camera: {
      profile_id: 'imx708-1080p50',
      bitrate_kbps: 6_000,
      gop: 25,
    },
    sub_stream: {
      enabled: true,
      width: 1280,
      height: 720,
      fps: 24,
      bitrate_kbps: 2_000,
    },
    models: [
      { id: 'objects', enabled: true, confidence_threshold: 0.4 },
      { id: 'pose', enabled: false, confidence_threshold: 0.5 },
    ],
  },
  pending: {
    camera: {
      profile_id: 'imx708-720p50',
      bitrate_kbps: 5_000,
      gop: 30,
    },
    sub_stream: {
      enabled: false,
      width: 640,
      height: 360,
      fps: 15,
      bitrate_kbps: 1_000,
    },
    models: [
      { id: 'objects', enabled: true, confidence_threshold: 0.45 },
      { id: 'pose', enabled: false, confidence_threshold: 0.55 },
    ],
  },
  last_apply: {
    status: 'failed',
    code: 'E_SETTINGS_APPLY_FAILED',
    restored: true,
  },
});

describe('runtime settings contracts', () => {
  it('parses the complete safe snapshot contract', () => {
    expect(parseRuntimeSettingsSnapshot(makeSnapshot())).toEqual(makeSnapshot());
  });

  it('reads active.sub_stream into typed settings', () => {
    const parsed = parseRuntimeSettingsSnapshot(makeSnapshot());
    expect(parsed.active.sub_stream).toEqual({
      enabled: true,
      width: 1280,
      height: 720,
      fps: 24,
      bitrate_kbps: 2_000,
    });
  });

  it('defaults sub_stream to disabled 640x360@15/1000kbps when absent', () => {
    const value = makeSnapshot();
    const { sub_stream: _activeSub, ...activeRest } = value.active;
    const { sub_stream: _pendingSub, ...pendingRest } = value.pending;
    const parsed = parseRuntimeSettingsSnapshot({
      ...value,
      active: activeRest,
      pending: pendingRest,
    });
    const defaultSubStream = {
      enabled: false,
      width: 640,
      height: 360,
      fps: 15,
      bitrate_kbps: 1_000,
    };
    expect(parsed.active.sub_stream).toEqual(defaultSubStream);
    expect(parsed.pending?.sub_stream).toEqual(defaultSubStream);
  });

  it('parses a successful apply outcome separately from the snapshot', () => {
    const response = { ...makeSnapshot(), state: 'clean', pending: null,
      last_apply: { status: 'success', code: '', restored: false },
      applied: true, restored: false };
    const { applied: _applied, restored: _restored, ...expectedSnapshot } = response;

    expect(parseRuntimeSettingsApplyResponse(response)).toEqual({
      snapshot: expectedSnapshot,
      applied: true,
      restored: false,
    });
  });

  it.each([
    ['missing member', () => {
      const { state: _state, ...value } = makeSnapshot();
      return value;
    }],
    ['unknown root member', () => ({ ...makeSnapshot(), private_path: '/opt/model.hef' })],
    ['unsafe revision', () => ({ ...makeSnapshot(), revision: Number.MAX_SAFE_INTEGER + 1 })],
    ['unknown state', () => ({ ...makeSnapshot(), state: 'restarting' })],
    ['fractional encoder value', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        camera: { ...makeSnapshot().active.camera, bitrate_kbps: 6_000.5 },
      },
    })],
    ['unknown profile', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        camera: { ...makeSnapshot().active.camera, profile_id: 'custom-mode' },
      },
    })],
    ['incomplete model set', () => ({
      ...makeSnapshot(),
      active: { ...makeSnapshot().active, models: makeSnapshot().active.models.slice(0, 1) },
    })],
    ['duplicate model IDs', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        models: [makeSnapshot().active.models[0], makeSnapshot().active.models[0]],
      },
    })],
    ['out-of-range confidence', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        models: [
          { ...makeSnapshot().active.models[0], confidence_threshold: 1.01 },
          makeSnapshot().active.models[1],
        ],
      },
    })],
    ['inconsistent last apply', () => ({
      ...makeSnapshot(),
      last_apply: { status: 'success', code: 'E_SETTINGS_APPLY_FAILED', restored: true },
    })],
    ['enabled sub_stream with an off-allowlist resolution', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        sub_stream: {
          enabled: true, width: 800, height: 600, fps: 24, bitrate_kbps: 2_000,
        },
      },
    })],
    ['enabled sub_stream with out-of-range fps', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        sub_stream: {
          enabled: true, width: 1280, height: 720, fps: 60, bitrate_kbps: 2_000,
        },
      },
    })],
    ['enabled sub_stream with out-of-range bitrate', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        sub_stream: {
          enabled: true, width: 1280, height: 720, fps: 24, bitrate_kbps: 100,
        },
      },
    })],
    ['sub_stream with a zero geometry field', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        sub_stream: {
          enabled: false, width: 0, height: 360, fps: 15, bitrate_kbps: 1_000,
        },
      },
    })],
  ])('rejects %s', (_name, mutate) => {
    expect(() => parseRuntimeSettingsSnapshot(mutate())).toThrow(
      'Invalid runtime settings response',
    );
  });

  it.each(['hef_path', 'output_name']) (
    'rejects backend-only model metadata field %s',
    (field) => {
      const value = makeSnapshot();
      const model = value.capabilities.models[0] as Record<string, unknown>;
      model[field] = field === 'hef_path' ? '/opt/models/object.hef' : 'output0';

      expect(() => parseRuntimeSettingsSnapshot(value)).toThrow(
        'Invalid runtime settings response',
      );
    },
  );
});
