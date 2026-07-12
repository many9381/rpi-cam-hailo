import type {
  AiModelStatus,
  AiRunnerStatus,
  AiStatus,
  CameraInventory,
  CameraStatus,
  Detection,
  DetectionEvent,
  DetectionKeypoint,
  DetectionSnapshot,
  HealthStatus,
  InitializeResult,
  LoginResult,
  LogoutResult,
  Principal,
  RestartAiResult,
  SetupStatus,
  StreamStatus,
} from './types';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isString = (value: unknown): value is string => typeof value === 'string';
const isFiniteNumber = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);
const isNonnegativeInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;

function invalid(message: string): never {
  throw new Error(message);
}

export function parseHealth(value: unknown): HealthStatus {
  if (!isRecord(value) || !isString(value.status)) {
    return invalid('Invalid health response');
  }
  return { status: value.status };
}

function parseCamera(value: unknown): CameraStatus {
  if (!isRecord(value) || !isString(value.id) || !isString(value.state) ||
      typeof value.snapshot_available !== 'boolean') {
    return invalid('Invalid camera response');
  }
  return {
    id: value.id,
    state: value.state,
    snapshot_available: value.snapshot_available,
  };
}

function parseAiModel(value: unknown): AiModelStatus {
  if (!isRecord(value) || !isString(value.id) || !isString(value.kind) ||
      !isNonnegativeInteger(value.input_width) ||
      !isNonnegativeInteger(value.input_height) ||
      !isString(value.input_format) || typeof value.letterbox !== 'boolean' ||
      !isString(value.output_name) || !isFiniteNumber(value.confidence_threshold) ||
      !isString(value.labels)) {
    return invalid('Invalid camera response');
  }
  return {
    id: value.id,
    kind: value.kind,
    input_width: value.input_width,
    input_height: value.input_height,
    input_format: value.input_format,
    letterbox: value.letterbox,
    output_name: value.output_name,
    confidence_threshold: value.confidence_threshold,
    labels: value.labels,
  };
}

function parseAiRunner(value: unknown): AiRunnerStatus {
  if (!isRecord(value) || !isString(value.camera_id) ||
      !isString(value.model_id) || !isString(value.model_kind) ||
      !isNonnegativeInteger(value.submitted_frames) ||
      !isNonnegativeInteger(value.processed_frames) ||
      !isNonnegativeInteger(value.dropped_frames) ||
      !isString(value.last_error_code) || !isString(value.last_error_message)) {
    return invalid('Invalid camera response');
  }
  return {
    camera_id: value.camera_id,
    model_id: value.model_id,
    model_kind: value.model_kind,
    submitted_frames: value.submitted_frames,
    processed_frames: value.processed_frames,
    dropped_frames: value.dropped_frames,
    last_error_code: value.last_error_code,
    last_error_message: value.last_error_message,
  };
}

function parseAi(value: unknown): AiStatus {
  if (!isRecord(value) || typeof value.enabled !== 'boolean' ||
      !isString(value.backend) || !isString(value.state) ||
      !isNonnegativeInteger(value.model_count) ||
      !isNonnegativeInteger(value.runner_count) || !isString(value.reason) ||
      !Array.isArray(value.models) || !Array.isArray(value.runners)) {
    return invalid('Invalid camera response');
  }
  return {
    enabled: value.enabled,
    backend: value.backend,
    state: value.state,
    model_count: value.model_count,
    runner_count: value.runner_count,
    reason: value.reason,
    models: value.models.map(parseAiModel),
    runners: value.runners.map(parseAiRunner),
  };
}

export function parseCameraInventory(value: unknown): CameraInventory {
  if (!isRecord(value) || !Array.isArray(value.cameras)) {
    return invalid('Invalid camera response');
  }
  return { cameras: value.cameras.map(parseCamera), ai: parseAi(value.ai) };
}

export function parseStream(value: unknown): StreamStatus {
  if (!isRecord(value) || !isString(value.url) ||
      typeof value.control_tls !== 'boolean' || typeof value.media_srtp !== 'boolean' ||
      !isRecord(value.secure_media) ||
      !isString(value.secure_media.control_scheme) ||
      !isString(value.secure_media.media_profile) ||
      !isString(value.secure_media.keying) ||
      typeof value.secure_media.requires_tls_control_channel !== 'boolean' ||
      (value.secure_media.per_media_key_zeroize_count !== undefined &&
       !isNonnegativeInteger(value.secure_media.per_media_key_zeroize_count))) {
    return invalid('Invalid stream response');
  }
  return {
    url: value.url,
    control_tls: value.control_tls,
    media_srtp: value.media_srtp,
    secure_media: {
      control_scheme: value.secure_media.control_scheme,
      media_profile: value.secure_media.media_profile,
      keying: value.secure_media.keying,
      requires_tls_control_channel:
        value.secure_media.requires_tls_control_channel,
      ...(value.secure_media.per_media_key_zeroize_count === undefined ? {} : {
        per_media_key_zeroize_count:
          value.secure_media.per_media_key_zeroize_count as number,
      }),
    },
  };
}

function parseKeypoint(value: unknown): DetectionKeypoint {
  if (!isRecord(value) || !isString(value.name) || !isFiniteNumber(value.x) ||
      !isFiniteNumber(value.y) || !isFiniteNumber(value.confidence)) {
    return invalid('Invalid detection response');
  }
  return { name: value.name, x: value.x, y: value.y, confidence: value.confidence };
}

function parseDetection(value: unknown): Detection {
  if (!isRecord(value) || !isString(value.label) ||
      !isFiniteNumber(value.confidence) || !isRecord(value.box) ||
      !isFiniteNumber(value.box.x) || !isFiniteNumber(value.box.y) ||
      !isFiniteNumber(value.box.width) || !isFiniteNumber(value.box.height) ||
      !Array.isArray(value.keypoints)) {
    return invalid('Invalid detection response');
  }
  return {
    label: value.label,
    confidence: value.confidence,
    box: { x: value.box.x, y: value.box.y,
      width: value.box.width, height: value.box.height },
    keypoints: value.keypoints.map(parseKeypoint),
  };
}

function parseDetectionEvent(value: unknown): DetectionEvent {
  if (!isRecord(value) || !isString(value.camera_id) ||
      !isString(value.model_id) || !isString(value.model_kind) ||
      !isString(value.result_state) || !isNonnegativeInteger(value.frame_sequence) ||
      !isFiniteNumber(value.frame_timestamp_ns) ||
      !Number.isInteger(value.frame_timestamp_ns) || !Array.isArray(value.detections)) {
    return invalid('Invalid detection response');
  }
  return {
    camera_id: value.camera_id,
    model_id: value.model_id,
    model_kind: value.model_kind,
    result_state: value.result_state,
    frame_sequence: value.frame_sequence,
    frame_timestamp_ns: value.frame_timestamp_ns,
    detections: value.detections.map(parseDetection),
  };
}

export function parseDetectionSnapshot(value: unknown): DetectionSnapshot {
  if (!isRecord(value) || !Array.isArray(value.events)) {
    return invalid('Invalid detection response');
  }
  return { events: value.events.map(parseDetectionEvent) };
}

export function parseRestartAiResult(value: unknown): RestartAiResult {
  if (!isRecord(value) || value.status !== 'restarted') {
    return invalid('Invalid AI restart response');
  }
  if (value.ai === undefined) {
    return { status: 'restarted' };
  }
  try {
    return { status: 'restarted', ai: parseAi(value.ai) };
  } catch {
    return invalid('Invalid AI restart response');
  }
}

export function parseSetupStatus(value: unknown): SetupStatus {
  if (!isRecord(value) || typeof value.required !== 'boolean') {
    throw new Error('Invalid setup status response');
  }

  if (value.required) {
    if ((value.phase !== 'administrator' && value.phase !== 'runtime_pending') ||
        value.tls !== 'ready' ||
        typeof value.peer_ip !== 'string' || value.peer_ip.length === 0) {
      throw new Error('Invalid setup status response');
    }
    return {
      required: true,
      phase: value.phase,
      tls: 'ready',
      peer_ip: value.peer_ip,
    };
  }

  if (value.phase !== undefined || value.tls !== undefined ||
      value.peer_ip !== undefined) {
    throw new Error('Invalid setup status response');
  }
  return { required: false };
}

export function parseInitializeResult(value: unknown): InitializeResult {
  if (!isRecord(value) || value.required !== false ||
      value.runtime !== 'running') {
    throw new Error('Invalid initialize response');
  }
  return { required: false, runtime: 'running' };
}

export function parsePrincipal(value: unknown): Principal {
  if (!isRecord(value) ||
      typeof value.username !== 'string' || value.username.length === 0 ||
      (value.role !== 'administrator' && value.role !== 'viewer')) {
    throw new Error('Invalid principal response');
  }
  return { username: value.username, role: value.role };
}

export function parseLoginResult(value: unknown): LoginResult {
  if (!isRecord(value) || value.role !== 'administrator' ||
      !Number.isSafeInteger(value.idle_expires_at_seconds) ||
      (value.idle_expires_at_seconds as number) < 0) {
    throw new Error('Invalid login response');
  }
  return {
    role: 'administrator',
    idle_expires_at_seconds: value.idle_expires_at_seconds as number,
  };
}

export function parseLogoutResult(value: unknown): LogoutResult {
  if (!isRecord(value) || value.logged_out !== true) {
    throw new Error('Invalid logout response');
  }
  return { logged_out: true };
}
