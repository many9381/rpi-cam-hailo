import { describe, expect, it } from 'vitest';

import {
  parseCameraInventory,
  parseDetectionSnapshot,
  parseHealth,
  parseInitializeResult,
  parseLoginResult,
  parseLogoutResult,
  parseRestartAiResult,
  parsePrincipal,
  parseSetupStatus,
  parseStream,
} from './contracts';

const ai = {
  enabled: true,
  backend: 'hailo',
  state: 'ready',
  model_count: 1,
  runner_count: 1,
  reason: 'AI runtime ready',
  models: [{
    id: 'objects', kind: 'object_detection', input_width: 640,
    input_height: 640, input_format: 'rgb8', letterbox: true,
    output_name: 'yolov8_nms_postprocess', confidence_threshold: 0.4,
    labels: 'coco80',
  }],
  runners: [{
    camera_id: 'imx708-main', model_id: 'objects',
    model_kind: 'object_detection', submitted_frames: 11,
    processed_frames: 10, dropped_frames: 1,
    last_error_code: '', last_error_message: '',
  }],
};

describe('operational response parsers', () => {
  it('validates health and the complete camera and AI inventory', () => {
    expect(parseHealth({ status: 'ok' })).toEqual({ status: 'ok' });
    expect(parseCameraInventory({
      cameras: [{ id: 'imx708-main', state: 'streaming', snapshot_available: true }],
      ai,
    })).toEqual({
      cameras: [{ id: 'imx708-main', state: 'streaming', snapshot_available: true }],
      ai,
    });
  });

  it('supports future model kinds without exposing model files', () => {
    const pose = {
      ...ai.models[0],
      id: 'pose',
      kind: 'pose',
      output_name: 'yolov8_pose_postprocess',
      labels: 'pose17',
    };
    const result = parseCameraInventory({
      cameras: [],
      ai: { ...ai, model_count: 2, models: [ai.models[0], pose] },
    });

    expect(result.ai.models.map((model) => model.kind)).toEqual([
      'object_detection', 'pose',
    ]);
    expect(result.ai.models[0]).not.toHaveProperty('hef_path');
  });

  it('preserves an optional safe nonnegative key zeroize count', () => {
    expect(parseStream({
      url: 'rtsps://camera.local:8555/imx708/main',
      control_tls: true,
      media_srtp: true,
      secure_media: {
        control_scheme: 'rtsps',
        media_profile: 'RTP/SAVPF',
        keying: 'SDES-over-RTSPS',
        requires_tls_control_channel: true,
        per_media_key_zeroize_count: 7,
      },
    }).secure_media.per_media_key_zeroize_count).toBe(7);

    expect(parseStream({
      url: 'rtsp://camera.local:8555/imx708/main',
      control_tls: false,
      media_srtp: false,
      secure_media: {
        control_scheme: 'rtsp', media_profile: 'RTP/AVP', keying: 'none',
        requires_tls_control_channel: false,
      },
    }).secure_media.per_media_key_zeroize_count).toBeUndefined();
  });

  it.each([-1, 1.5, Number.POSITIVE_INFINITY])(
    'rejects unsafe key zeroize count %s',
    (count) => {
      expect(() => parseStream({
        url: 'rtsps://camera.local:8555/imx708/main',
        control_tls: true,
        media_srtp: true,
        secure_media: {
          control_scheme: 'rtsps', media_profile: 'RTP/SAVPF',
          keying: 'SDES-over-RTSPS', requires_tls_control_channel: true,
          per_media_key_zeroize_count: count,
        },
      })).toThrow('Invalid stream response');
    },
  );

  it('validates the initial detection snapshot shape', () => {
    expect(parseDetectionSnapshot({ events: [{
      camera_id: 'imx708-main', model_id: 'objects',
      model_kind: 'object_detection', result_state: 'decoded',
      frame_sequence: 12, frame_timestamp_ns: 123456,
      detections: [{
        label: 'person', confidence: 0.9,
        box: { x: 0.1, y: 0.2, width: 0.3, height: 0.4 },
        keypoints: [],
      }],
    }] }).events).toHaveLength(1);
  });

  it('validates restart results with and without replacement AI status', () => {
    expect(parseRestartAiResult({ status: 'restarted' })).toEqual({
      status: 'restarted',
    });
    expect(parseRestartAiResult({ status: 'restarted', ai })).toEqual({
      status: 'restarted', ai,
    });
  });

  it.each([
    null,
    {},
    { status: 'starting' },
    { status: 'restarted', ai: { ...ai, models: 'invalid' } },
  ])('rejects malformed restart result %#', (value) => {
    expect(() => parseRestartAiResult(value)).toThrow('Invalid AI restart response');
  });

  it.each([
    null,
    {},
    { cameras: 'invalid', ai },
    { cameras: [], ai: { ...ai, enabled: 'yes' } },
    { cameras: [], ai: { ...ai, models: [{ ...ai.models[0], input_width: -1 }] } },
    { cameras: [], ai: { ...ai, runners: [{ ...ai.runners[0], dropped_frames: -1 }] } },
  ])('rejects malformed camera inventory %#', (value) => {
    expect(() => parseCameraInventory(value)).toThrow('Invalid camera response');
  });

  it.each([null, {}, { status: 7 }])('rejects malformed health %#', (value) => {
    expect(() => parseHealth(value)).toThrow('Invalid health response');
  });

  it.each([null, {}, { events: {} }, { events: [{ camera_id: 'cam' }] }])(
    'rejects malformed detection snapshot %#',
    (value) => {
      expect(() => parseDetectionSnapshot(value)).toThrow('Invalid detection response');
    },
  );
});

describe('parseInitializeResult', () => {
  it('accepts the running runtime state', () => {
    expect(parseInitializeResult({ required: false, runtime: 'running' })).toEqual({
      required: false,
      runtime: 'running',
    });
  });

  it.each([
    null,
    {},
    { required: true, runtime: 'running' },
    { required: false, runtime: 'deferred' },
    { required: false, runtime: 'stopped' },
  ])('rejects malformed initialize result %#', (value) => {
    expect(() => parseInitializeResult(value)).toThrow('Invalid initialize response');
  });
});

describe('parseSetupStatus', () => {
  it('accepts setup-required and operational responses', () => {
    expect(parseSetupStatus({
      required: true,
      phase: 'administrator',
      tls: 'ready',
      peer_ip: '192.0.2.10',
    })).toEqual({
      required: true,
      phase: 'administrator',
      tls: 'ready',
      peer_ip: '192.0.2.10',
    });
    expect(parseSetupStatus({
      required: true,
      phase: 'runtime_pending',
      tls: 'ready',
      peer_ip: '192.0.2.10',
    })).toEqual({
      required: true,
      phase: 'runtime_pending',
      tls: 'ready',
      peer_ip: '192.0.2.10',
    });
    expect(parseSetupStatus({ required: false })).toEqual({ required: false });
  });

  it.each([
    null,
    {},
    { required: 'true', tls: 'ready', peer_ip: '192.0.2.10' },
    { required: true, tls: 'pending', peer_ip: '192.0.2.10' },
    { required: true, tls: 'ready' },
    { required: true, tls: 'ready', peer_ip: 42 },
    { required: true, phase: 'unknown', tls: 'ready', peer_ip: '192.0.2.10' },
    { required: false, peer_ip: '192.0.2.10' },
  ])('rejects malformed setup status %#', (value) => {
    expect(() => parseSetupStatus(value)).toThrow('Invalid setup status response');
  });
});

describe('parsePrincipal', () => {
  it.each(['administrator', 'viewer'] as const)('accepts the %s role', (role) => {
    expect(parsePrincipal({ username: 'operator.one', role })).toEqual({
      username: 'operator.one',
      role,
    });
  });

  it.each([
    null,
    {},
    { username: '', role: 'administrator' },
    { username: 'operator.one', role: 'operator' },
    { username: 42, role: 'viewer' },
  ])('rejects malformed principal %#', (value) => {
    expect(() => parsePrincipal(value)).toThrow('Invalid principal response');
  });
});

describe('parseLoginResult', () => {
  it('accepts an administrator login result', () => {
    expect(parseLoginResult({
      role: 'administrator',
      idle_expires_at_seconds: 100,
    })).toEqual({ role: 'administrator', idle_expires_at_seconds: 100 });
  });

  it.each([
    null,
    { role: 'viewer', idle_expires_at_seconds: 100 },
    { role: 'administrator', idle_expires_at_seconds: -1 },
    { role: 'administrator', idle_expires_at_seconds: 1.5 },
    { role: 'administrator', idle_expires_at_seconds: Number.POSITIVE_INFINITY },
  ])('rejects malformed login result %#', (value) => {
    expect(() => parseLoginResult(value)).toThrow('Invalid login response');
  });
});

describe('parseLogoutResult', () => {
  it('accepts only an authoritative logout result', () => {
    expect(parseLogoutResult({ logged_out: true })).toEqual({ logged_out: true });
  });

  it.each([null, {}, { logged_out: false }, { logged_out: 'true' }])(
    'rejects malformed logout result %#',
    (value) => {
      expect(() => parseLogoutResult(value)).toThrow('Invalid logout response');
    },
  );
});
