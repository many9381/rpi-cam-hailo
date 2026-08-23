import { describe, expect, it } from 'vitest';

import {
  parseCameraInventory,
  parseDetectionSnapshot,
  parseHealth,
  parseInitializeResult,
  parseLoginResult,
  parseLogoutResult,
  parseMonitoringCameras,
  parseRestartAiResult,
  parseRuntimeRestartResult,
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
    last_preprocess_ms: 1.2, last_inference_ms: 3.4,
    last_processed_sequence: 11,
    last_error_code: '', last_error_message: '',
  }],
};

const detectionSnapshot = {
  events: [{
    camera_id: 'imx708-main',
    model_id: 'objects',
    model_kind: 'object_detection',
    result_state: 'decoded',
    frame_sequence: 12,
    frame_timestamp_ns: 123456,
    detections: [{
      class_id: 2,
      label: 'person',
      confidence: 0.9,
      box: { x: 0.1, y: 0.2, width: 0.3, height: 0.4 },
      keypoints: [{
        name: 'nose', x: 0.2, y: 0.3, confidence: 0.8,
      }],
    }],
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

  it('parses per-camera encoder health metrics when present', () => {
    const result = parseCameraInventory({
      cameras: [{
        id: 'imx708-main', state: 'streaming', snapshot_available: true,
        capture_fps: 49.8, encoded_fps: 49.7, last_encode_ms: 7.25,
      }],
      ai,
    });
    expect(result.cameras[0].capture_fps).toBeCloseTo(49.8);
    expect(result.cameras[0].encoded_fps).toBeCloseTo(49.7);
    expect(result.cameras[0].last_encode_ms).toBeCloseTo(7.25);
  });

  it('rejects malformed encoder health metrics', () => {
    expect(() => parseCameraInventory({
      cameras: [{
        id: 'imx708-main', state: 'streaming', snapshot_available: true,
        capture_fps: 'fast',
      }],
      ai,
    })).toThrow('Invalid camera response');
    expect(() => parseCameraInventory({
      cameras: [{
        id: 'imx708-main', state: 'streaming', snapshot_available: true,
        last_encode_ms: -1,
      }],
      ai,
    })).toThrow('Invalid camera response');
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

  it('rejects AI runner timings and sequence outside their strict ranges', () => {
    expect(() => parseCameraInventory({
      cameras: [],
      ai: { ...ai, runners: [{ ...ai.runners[0], last_inference_ms: -1 }] },
    })).toThrow('Invalid camera response');
    expect(() => parseCameraInventory({
      cameras: [],
      ai: { ...ai, runners: [{ ...ai.runners[0], last_processed_sequence: 1.5 }] },
    })).toThrow('Invalid camera response');
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
    expect(parseDetectionSnapshot(detectionSnapshot)
      .events[0].detections[0].class_id).toBe(2);
  });

  it.each([
    ['snapshot', () => ({ ...detectionSnapshot, token: 'viewer-secret' })],
    ['event', () => ({ events: [{
      ...detectionSnapshot.events[0], token: 'viewer-secret',
    }] })],
    ['detection', () => ({ events: [{
      ...detectionSnapshot.events[0],
      detections: [{
        ...detectionSnapshot.events[0].detections[0], hash: 'viewer-secret',
      }],
    }] })],
    ['box', () => ({ events: [{
      ...detectionSnapshot.events[0],
      detections: [{
        ...detectionSnapshot.events[0].detections[0],
        box: {
          ...detectionSnapshot.events[0].detections[0].box,
          salt: 'viewer-secret',
        },
      }],
    }] })],
    ['keypoint', () => ({ events: [{
      ...detectionSnapshot.events[0],
      detections: [{
        ...detectionSnapshot.events[0].detections[0],
        keypoints: [{
          ...detectionSnapshot.events[0].detections[0].keypoints[0],
          password: 'viewer-secret',
        }],
      }],
    }] })],
  ])('rejects an unknown field at the %s level', (_level, makeValue) => {
    expect(() => parseDetectionSnapshot(makeValue()))
      .toThrow('Invalid detection response');
  });

  it('rejects detection snapshots with invalid class IDs', () => {
    expect(() => parseDetectionSnapshot({ events: [{
      camera_id: 'imx708-main', model_id: 'objects',
      model_kind: 'object_detection', result_state: 'decoded',
      frame_sequence: 12, frame_timestamp_ns: 123456,
      detections: [{
        class_id: -1,
        label: 'person', confidence: 0.9,
        box: { x: 0.1, y: 0.2, width: 0.3, height: 0.4 },
        keypoints: [],
      }],
    }] })).toThrow('Invalid detection response');
  });

  it('validates restart results with and without replacement AI status', () => {
    expect(parseRestartAiResult({ status: 'restarted' })).toEqual({
      status: 'restarted',
    });
    expect(parseRestartAiResult({ status: 'restarted', ai })).toEqual({
      status: 'restarted', ai,
    });
  });

  it('accepts only a running runtime restart response', () => {
    expect(parseRuntimeRestartResult({ runtime: 'running' })).toEqual({
      runtime: 'running',
    });
    expect(() => parseRuntimeRestartResult({ runtime: 'failed' }))
      .toThrow('Invalid runtime restart response');
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
      initial_username: null,
      initial_password: null,
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
      initial_username: null,
      initial_password: null,
    });
    expect(parseSetupStatus({ required: false })).toEqual({ required: false });
  });

  it('parses the initial credential while the device is uninitialized in the administrator phase', () => {
    expect(parseSetupStatus({
      required: true,
      phase: 'administrator',
      tls: 'ready',
      peer_ip: '192.0.2.10',
      initial_username: 'setup.x7k2q',
      initial_password: 'T4m#pR9vLw',
    })).toEqual({
      required: true,
      phase: 'administrator',
      tls: 'ready',
      peer_ip: '192.0.2.10',
      initial_username: 'setup.x7k2q',
      initial_password: 'T4m#pR9vLw',
    });
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
    { required: true, phase: 'administrator', tls: 'ready', peer_ip: '192.0.2.10',
      initial_username: 'setup.x7k2q' },
    { required: true, phase: 'administrator', tls: 'ready', peer_ip: '192.0.2.10',
      initial_password: 'T4m#pR9vLw' },
    { required: true, phase: 'administrator', tls: 'ready', peer_ip: '192.0.2.10',
      initial_username: '', initial_password: 'T4m#pR9vLw' },
    { required: true, phase: 'administrator', tls: 'ready', peer_ip: '192.0.2.10',
      initial_username: 'setup.x7k2q', initial_password: '' },
    { required: true, phase: 'administrator', tls: 'ready', peer_ip: '192.0.2.10',
      initial_username: 42, initial_password: 'T4m#pR9vLw' },
    { required: true, phase: 'runtime_pending', tls: 'ready', peer_ip: '192.0.2.10',
      initial_username: 'setup.x7k2q', initial_password: 'T4m#pR9vLw' },
    { required: false, initial_username: 'setup.x7k2q', initial_password: 'T4m#pR9vLw' },
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
    { username: 'operator.one', role: 'viewer', token: 'not-returned' },
  ])('rejects malformed principal %#', (value) => {
    expect(() => parsePrincipal(value)).toThrow('Invalid principal response');
  });
});

describe('parseLoginResult', () => {
  it.each(['administrator', 'viewer'] as const)('accepts a %s login result', (role) => {
    const value = { role, idle_expires_at_seconds: 100 };

    const result = parseLoginResult(value);

    expect(result).toEqual(value);
    expect(result).not.toBe(value);
  });

  it.each([
    null,
    {},
    { role: 'operator', idle_expires_at_seconds: 100 },
    { role: 'administrator', idle_expires_at_seconds: -1 },
    { role: 'administrator', idle_expires_at_seconds: 1.5 },
    { role: 'administrator', idle_expires_at_seconds: Number.POSITIVE_INFINITY },
    { role: 'viewer', idle_expires_at_seconds: 100, password: 'not-returned' },
  ])('rejects malformed login result %#', (value) => {
    expect(() => parseLoginResult(value)).toThrow('Invalid login response');
  });
});

describe('parseMonitoringCameras', () => {
  const camera = {
    id: 'imx708-main',
    state: 'running',
    width: 1920,
    height: 1080,
    snapshot_available: true,
  };

  it('accepts only the public monitoring projection as fresh values', () => {
    const value = { cameras: [camera] };

    const result = parseMonitoringCameras(value);

    expect(result).toEqual(value);
    expect(result).not.toBe(value);
    expect(result.cameras).not.toBe(value.cameras);
    expect(result.cameras[0]).not.toBe(camera);
  });

  it.each([
    ['missing camera key', () => ({ cameras: [{ ...camera, width: undefined }] })],
    ['unknown root key', () => ({ cameras: [camera], ai: {} })],
    ['unknown credential field', () => ({ cameras: [{ ...camera, password: 'viewer-secret' }] })],
    ['credential hash field', () => ({ cameras: [{ ...camera, hash: 'viewer-secret' }] })],
    ['credential salt field', () => ({ cameras: [{ ...camera, salt: 'viewer-secret' }] })],
    ['empty identifier', () => ({ cameras: [{ ...camera, id: '' }] })],
    ['empty state', () => ({ cameras: [{ ...camera, state: '' }] })],
    ['negative width', () => ({ cameras: [{ ...camera, width: -1 }] })],
    ['fractional height', () => ({ cameras: [{ ...camera, height: 1.5 }] })],
    ['unsafe width', () => ({ cameras: [{ ...camera, width: Number.MAX_SAFE_INTEGER + 1 }] })],
    ['invalid snapshot flag', () => ({ cameras: [{ ...camera, snapshot_available: 'true' }] })],
  ])('rejects %s without echoing rejected data', (_name, makeValue) => {
    const value = makeValue();
    let error: unknown;

    try {
      parseMonitoringCameras(value);
    } catch (caught) {
      error = caught;
    }

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe('Invalid monitoring cameras response');
    expect((error as Error).message).not.toContain('viewer-secret');
  });
});

describe('parseLogoutResult', () => {
  it('accepts only an authoritative logout result', () => {
    expect(parseLogoutResult({ logged_out: true })).toEqual({ logged_out: true });
  });

  it.each([
    null,
    {},
    { logged_out: false },
    { logged_out: 'true' },
    { logged_out: true, token: 'not-returned' },
  ])(
    'rejects malformed logout result %#',
    (value) => {
      expect(() => parseLogoutResult(value)).toThrow('Invalid logout response');
    },
  );
});
