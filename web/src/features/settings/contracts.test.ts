import { describe, expect, it } from 'vitest';

import {
  MAX_OSD_ITEMS,
  type OsdItem,
  type OsdRuntimeSettings,
  isOsdSettingsValid,
  osdSettingsEqual,
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
    osd: {
      enabled: true,
      items: [
        { type: 'timestamp', text: '', position: 'top_left' },
        { type: 'custom_text', text: 'Front Porch', position: 'bottom_right' },
      ],
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
    osd: {
      enabled: false,
      items: [
        { type: 'camera_name', text: '', position: 'top_right' },
      ],
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

  it('reads active.osd into typed settings', () => {
    const parsed = parseRuntimeSettingsSnapshot(makeSnapshot());
    expect(parsed.active.osd).toEqual({
      enabled: true,
      items: [
        { type: 'timestamp', text: '', position: 'top_left' },
        { type: 'custom_text', text: 'Front Porch', position: 'bottom_right' },
      ],
    });
  });

  it('parses a disabled sub_stream with off-allowlist geometry (allowlist bypassed while disabled)', () => {
    const parsed = parseRuntimeSettingsSnapshot({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        sub_stream: {
          enabled: false, width: 800, height: 600, fps: 15, bitrate_kbps: 1_000,
        },
      },
    });
    expect(parsed.active.sub_stream).toEqual({
      enabled: false, width: 800, height: 600, fps: 15, bitrate_kbps: 1_000,
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

  it('defaults osd to disabled with no items when absent', () => {
    const value = makeSnapshot();
    const { osd: _activeOsd, ...activeRest } = value.active;
    const { osd: _pendingOsd, ...pendingRest } = value.pending;
    const parsed = parseRuntimeSettingsSnapshot({
      ...value,
      active: activeRest,
      pending: pendingRest,
    });
    const defaultOsd = { enabled: false, items: [] };
    expect(parsed.active.osd).toEqual(defaultOsd);
    expect(parsed.pending?.osd).toEqual(defaultOsd);
  });

  it('never aliases a shared items array across defaulted osd results', () => {
    const value = makeSnapshot();
    const { osd: _activeOsd, ...activeRest } = value.active;
    const { osd: _pendingOsd, ...pendingRest } = value.pending;
    const withoutOsd = { ...value, active: activeRest, pending: pendingRest };

    const first = parseRuntimeSettingsSnapshot(withoutOsd);
    first.active.osd.items.push({ type: 'timestamp', text: '', position: 'top_left' });

    expect(first.active.osd.items).toHaveLength(1);
    // A sibling default from the very same parse call must not be the same array.
    expect(first.pending?.osd.items).toHaveLength(0);

    // A wholly independent parse call must not observe the mutation either -
    // proves the shared module-level default itself was never mutated.
    const second = parseRuntimeSettingsSnapshot(withoutOsd);
    expect(second.active.osd.items).toHaveLength(0);
    expect(second.pending?.osd.items).toHaveLength(0);
  });

  it('parses osd text at exactly the 64-byte UTF-8 boundary', () => {
    const text = 'x'.repeat(64);
    const parsed = parseRuntimeSettingsSnapshot({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'custom_text', text, position: 'top_left' }],
        },
      },
    });
    expect(parsed.active.osd.items).toEqual([
      { type: 'custom_text', text, position: 'top_left' },
    ]);
  });

  describe('isOsdSettingsValid', () => {
    const custom = (text: string): OsdItem => ({ type: 'custom_text', text, position: 'top_left' });

    it('accepts items the backend accepts, including a timestamp with empty text', () => {
      expect(isOsdSettingsValid({ enabled: true, items: [
        { type: 'timestamp', text: '', position: 'top_right' },
        { type: 'camera_name', text: '', position: 'bottom_left' },
        custom('Front door'),
      ] })).toBe(true);
      expect(isOsdSettingsValid({ enabled: false, items: [] })).toBe(true);
    });

    it('rejects a custom text item with no text, even while OSD is disabled', () => {
      expect(isOsdSettingsValid({ enabled: true, items: [custom('')] })).toBe(false);
      expect(isOsdSettingsValid({ enabled: false, items: [custom('')] })).toBe(false);
    });

    it('rejects more than MAX_OSD_ITEMS items', () => {
      const items = Array.from({ length: MAX_OSD_ITEMS + 1 }, () => custom('x'));
      expect(isOsdSettingsValid({ enabled: true, items })).toBe(false);
      expect(isOsdSettingsValid({ enabled: true, items: items.slice(0, MAX_OSD_ITEMS) })).toBe(true);
    });

    it('rejects text over 64 UTF-8 bytes or containing control characters', () => {
      expect(isOsdSettingsValid({ enabled: true, items: [custom('가'.repeat(22))] })).toBe(false);
      expect(isOsdSettingsValid({ enabled: true, items: [custom('가'.repeat(21))] })).toBe(true);
      expect(isOsdSettingsValid({ enabled: true, items: [custom('a\tb')] })).toBe(false);
    });
  });

  describe('osdSettingsEqual', () => {
    const base: OsdRuntimeSettings = {
      enabled: true,
      items: [{ type: 'custom_text', text: 'Front door', position: 'top_left' }],
    };

    it('treats structurally identical settings as equal', () => {
      expect(osdSettingsEqual(base, { enabled: true, items: [{ ...base.items[0] }] })).toBe(true);
    });

    it('detects a changed flag, item, or item count', () => {
      expect(osdSettingsEqual(base, { ...base, enabled: false })).toBe(false);
      expect(osdSettingsEqual(base, { enabled: true, items: [{ ...base.items[0], text: 'Back door' }] })).toBe(false);
      expect(osdSettingsEqual(base, { enabled: true, items: [] })).toBe(false);
    });
  });

  it('round-trips osd through a JSON PUT payload', () => {
    const value = makeSnapshot();
    const draft = parseRuntimeSettingsSnapshot(value).active;
    const putBody = { expected_revision: value.revision, settings: draft };
    const onWire = JSON.parse(JSON.stringify(putBody)) as typeof putBody;
    expect(onWire.settings.osd).toEqual(draft.osd);

    const reparsed = parseRuntimeSettingsSnapshot({ ...value, active: onWire.settings });
    expect(reparsed.active.osd).toEqual(draft.osd);
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
    ['osd with an extra key', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: { ...makeSnapshot().active.osd, extra: 'unexpected' },
      },
    })],
    ['osd items not an array', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: { enabled: true, items: 'nope' },
      },
    })],
    ['osd item with an extra key', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'timestamp', text: '', position: 'top_left', extra: 'unexpected' }],
        },
      },
    })],
    ['osd item with an unknown type', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'weather', text: '', position: 'top_left' }],
        },
      },
    })],
    ['osd item with an unknown position', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'timestamp', text: '', position: 'middle_center' }],
        },
      },
    })],
    ['osd item with non-string text', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'timestamp', text: 42, position: 'top_left' }],
        },
      },
    })],
    ['osd with 9 items (exceeds the 8-item maximum)', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: Array.from({ length: 9 }, () => (
            { type: 'timestamp', text: '', position: 'top_left' }
          )),
        },
      },
    })],
    ['osd item with 65-char text (exceeds the 64-char maximum)', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'custom_text', text: 'x'.repeat(65), position: 'top_left' }],
        },
      },
    })],
    ['osd item text exceeding 64 UTF-8 bytes despite being under 64 UTF-16 units', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          // 30 Hangul syllables: 30 UTF-16 units (well under 64) but 90 UTF-8 bytes.
          items: [{ type: 'custom_text', text: '가'.repeat(30), position: 'top_left' }],
        },
      },
    })],
    ['osd item text containing a newline control character', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'custom_text', text: 'front\nporch', position: 'top_left' }],
        },
      },
    })],
    ['osd item text containing a DEL control character', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'custom_text', text: 'front\x7Fporch', position: 'top_left' }],
        },
      },
    })],
    ['osd item with empty custom_text text', () => ({
      ...makeSnapshot(),
      active: {
        ...makeSnapshot().active,
        osd: {
          enabled: true,
          items: [{ type: 'custom_text', text: '', position: 'top_left' }],
        },
      },
    })],
    ['settings object with an extra key that is not sub_stream or osd', () => {
      const { sub_stream: _subStream, osd: _osd, ...rest } = makeSnapshot().active;
      return {
        ...makeSnapshot(),
        active: { ...rest, bogus: 'unexpected' },
      };
    }],
    ['settings object with an unrecognized extra key alongside sub_stream and osd', () => ({
      ...makeSnapshot(),
      active: { ...makeSnapshot().active, extra: 'unexpected' },
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
