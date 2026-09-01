export type RuntimeSettingsState =
  | 'clean'
  | 'pending'
  | 'applying'
  | 'failed'
  | 'recovery_required';

export interface CameraRuntimeSettings {
  profile_id: string;
  bitrate_kbps: number;
  gop: number;
}

export interface SubStreamRuntimeSettings {
  enabled: boolean;
  width: number;
  height: number;
  fps: number;
  bitrate_kbps: number;
}

export type OsdItemType = 'timestamp' | 'camera_name' | 'custom_text';
export type OsdPosition = 'top_left' | 'top_right' | 'bottom_left' | 'bottom_right';

export interface OsdItem {
  type: OsdItemType;
  text: string;
  position: OsdPosition;
}

export interface OsdRuntimeSettings {
  enabled: boolean;
  items: OsdItem[];
}

export interface ModelRuntimeSettings {
  id: string;
  enabled: boolean;
  confidence_threshold: number;
}

export interface RuntimeSettings {
  camera: CameraRuntimeSettings;
  sub_stream: SubStreamRuntimeSettings;
  osd: OsdRuntimeSettings;
  models: ModelRuntimeSettings[];
}

export const SUB_STREAM_RESOLUTIONS = [
  { width: 640, height: 360 },
  { width: 854, height: 480 },
  { width: 1280, height: 720 },
] as const;

export const SUB_STREAM_FPS_RANGE = { minimum: 5, maximum: 30 } as const;

export const OSD_ITEM_TYPES: readonly OsdItemType[] = ['timestamp', 'camera_name', 'custom_text'];
export const OSD_POSITIONS: readonly OsdPosition[] =
  ['top_left', 'top_right', 'bottom_left', 'bottom_right'];
export const MAX_OSD_ITEMS = 8;
export const MAX_OSD_TEXT = 64;

export interface CameraProfileCapability {
  id: string;
  width: number;
  height: number;
  fps: number;
  label: string;
}

export interface NumericCapability {
  minimum: number;
  maximum: number;
}

export interface ModelCapability {
  id: string;
  kind: string;
  input_width: number;
  input_height: number;
  input_format: string;
  letterbox: boolean;
  labels: string;
}

export interface RuntimeSettingsCapabilities {
  camera_profiles: CameraProfileCapability[];
  bitrate_kbps: NumericCapability;
  gop: NumericCapability;
  models: ModelCapability[];
}

export type LastApply =
  | { status: 'never' | 'success'; code: ''; restored: false }
  | {
      status: 'failed';
      code: 'E_SETTINGS_APPLY_FAILED';
      restored: boolean;
    };

export interface RuntimeSettingsSnapshot {
  schema_version: 1;
  revision: number;
  state: RuntimeSettingsState;
  capabilities: RuntimeSettingsCapabilities;
  active: RuntimeSettings;
  pending: RuntimeSettings | null;
  last_apply: LastApply;
}

export interface RuntimeSettingsApplyResponse {
  snapshot: RuntimeSettingsSnapshot;
  applied: true;
  restored: false;
}

export type RuntimeSettingsErrorCode =
  | 'E_SETTINGS_REQUEST_INVALID'
  | 'E_SETTINGS_REVISION_CONFLICT'
  | 'E_SETTINGS_NO_PENDING'
  | 'E_SETTINGS_BUSY'
  | 'E_SETTINGS_UNSUPPORTED'
  | 'E_SETTINGS_STORE'
  | 'E_SETTINGS_APPLY_FAILED'
  | 'E_SETTINGS_UNAVAILABLE'
  | 'E_SETTINGS_REQUEST_FAILED';

export interface PublicApiError {
  status: number;
  code: RuntimeSettingsErrorCode;
}

const snapshotKeys = [
  'schema_version',
  'revision',
  'state',
  'capabilities',
  'active',
  'pending',
  'last_apply',
] as const;

const settingsErrorCodes = new Set<RuntimeSettingsErrorCode>([
  'E_SETTINGS_REQUEST_INVALID',
  'E_SETTINGS_REVISION_CONFLICT',
  'E_SETTINGS_NO_PENDING',
  'E_SETTINGS_BUSY',
  'E_SETTINGS_UNSUPPORTED',
  'E_SETTINGS_STORE',
  'E_SETTINGS_APPLY_FAILED',
  'E_SETTINGS_UNAVAILABLE',
  'E_SETTINGS_REQUEST_FAILED',
]);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const hasExactKeys = (
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> => isRecord(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));

const hasKeysWithOptional = (
  value: unknown,
  keys: readonly string[],
  optionalKeys: readonly string[],
): value is Record<string, unknown> => {
  if (!isRecord(value) ||
      !keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))) {
    return false;
  }
  const allowed = new Set([...keys, ...optionalKeys]);
  return Object.keys(value).every((key) => allowed.has(key));
};

const isNonemptyString = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0;

const isSafeNonnegativeInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;

const isSafePositiveInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) > 0;

const isConfidence = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;

function invalid(): never {
  throw new Error('Invalid runtime settings response');
}

function parseNumericCapability(value: unknown): NumericCapability {
  if (!hasExactKeys(value, ['minimum', 'maximum']) ||
      !isSafePositiveInteger(value.minimum) ||
      !isSafePositiveInteger(value.maximum) ||
      value.minimum > value.maximum) {
    return invalid();
  }
  return { minimum: value.minimum, maximum: value.maximum };
}

function parseCameraProfile(value: unknown): CameraProfileCapability {
  if (!hasExactKeys(value, ['id', 'width', 'height', 'fps', 'label']) ||
      !isNonemptyString(value.id) || !isSafePositiveInteger(value.width) ||
      !isSafePositiveInteger(value.height) || !isSafePositiveInteger(value.fps) ||
      !isNonemptyString(value.label)) {
    return invalid();
  }
  return {
    id: value.id,
    width: value.width,
    height: value.height,
    fps: value.fps,
    label: value.label,
  };
}

function parseModelCapability(value: unknown): ModelCapability {
  if (!hasExactKeys(value, [
    'id', 'kind', 'input_width', 'input_height', 'input_format', 'letterbox',
    'labels',
  ]) || !isNonemptyString(value.id) || !isNonemptyString(value.kind) ||
      !isSafePositiveInteger(value.input_width) ||
      !isSafePositiveInteger(value.input_height) ||
      !isNonemptyString(value.input_format) || typeof value.letterbox !== 'boolean' ||
      typeof value.labels !== 'string') {
    return invalid();
  }
  return {
    id: value.id,
    kind: value.kind,
    input_width: value.input_width,
    input_height: value.input_height,
    input_format: value.input_format,
    letterbox: value.letterbox,
    labels: value.labels,
  };
}

function requireUniqueIds(values: readonly { id: string }[]): void {
  if (new Set(values.map(({ id }) => id)).size !== values.length) {
    invalid();
  }
}

function parseCapabilities(value: unknown): RuntimeSettingsCapabilities {
  if (!hasExactKeys(value, ['camera_profiles', 'bitrate_kbps', 'gop', 'models']) ||
      !Array.isArray(value.camera_profiles) || value.camera_profiles.length === 0 ||
      !Array.isArray(value.models)) {
    return invalid();
  }
  const cameraProfiles = value.camera_profiles.map(parseCameraProfile);
  const models = value.models.map(parseModelCapability);
  requireUniqueIds(cameraProfiles);
  requireUniqueIds(models);
  return {
    camera_profiles: cameraProfiles,
    bitrate_kbps: parseNumericCapability(value.bitrate_kbps),
    gop: parseNumericCapability(value.gop),
    models,
  };
}

const DEFAULT_SUB_STREAM: SubStreamRuntimeSettings = {
  enabled: false,
  width: 640,
  height: 360,
  fps: 15,
  bitrate_kbps: 1000,
};

const DEFAULT_OSD: OsdRuntimeSettings = { enabled: false, items: [] };

function parseSubStream(
  value: unknown,
  capabilities: RuntimeSettingsCapabilities,
): SubStreamRuntimeSettings {
  if (value === undefined) {
    return { ...DEFAULT_SUB_STREAM };
  }
  if (!hasExactKeys(value, ['enabled', 'width', 'height', 'fps', 'bitrate_kbps']) ||
      typeof value.enabled !== 'boolean' ||
      !isSafePositiveInteger(value.width) ||
      !isSafePositiveInteger(value.height) ||
      !isSafePositiveInteger(value.fps) ||
      !isSafePositiveInteger(value.bitrate_kbps)) {
    return invalid();
  }
  if (value.enabled) {
    const allowedResolution = SUB_STREAM_RESOLUTIONS.some(
      (resolution) => resolution.width === value.width && resolution.height === value.height,
    );
    if (!allowedResolution ||
        value.fps < SUB_STREAM_FPS_RANGE.minimum ||
        value.fps > SUB_STREAM_FPS_RANGE.maximum ||
        value.bitrate_kbps < capabilities.bitrate_kbps.minimum ||
        value.bitrate_kbps > capabilities.bitrate_kbps.maximum) {
      return invalid();
    }
  }
  return {
    enabled: value.enabled,
    width: value.width,
    height: value.height,
    fps: value.fps,
    bitrate_kbps: value.bitrate_kbps,
  };
}

function parseOsdItem(value: unknown): OsdItem {
  if (!hasExactKeys(value, ['type', 'text', 'position']) ||
      typeof value.type !== 'string' || typeof value.text !== 'string' ||
      typeof value.position !== 'string' ||
      !OSD_ITEM_TYPES.includes(value.type as OsdItemType) ||
      !OSD_POSITIONS.includes(value.position as OsdPosition) ||
      value.text.length > MAX_OSD_TEXT ||
      (value.type === 'custom_text' && value.text.length === 0)) {
    return invalid();
  }
  return {
    type: value.type as OsdItemType,
    text: value.text,
    position: value.position as OsdPosition,
  };
}

function parseOsd(value: unknown): OsdRuntimeSettings {
  if (value === undefined) {
    return { ...DEFAULT_OSD };
  }
  if (!hasExactKeys(value, ['enabled', 'items']) ||
      typeof value.enabled !== 'boolean' || !Array.isArray(value.items) ||
      value.items.length > MAX_OSD_ITEMS) {
    return invalid();
  }
  return { enabled: value.enabled, items: value.items.map(parseOsdItem) };
}

function parseRuntimeSettings(
  value: unknown,
  capabilities: RuntimeSettingsCapabilities,
): RuntimeSettings {
  if (!hasKeysWithOptional(value, ['camera', 'models'], ['sub_stream', 'osd']) ||
      !hasExactKeys(value.camera, ['profile_id', 'bitrate_kbps', 'gop']) ||
      !isNonemptyString(value.camera.profile_id) ||
      !isSafePositiveInteger(value.camera.bitrate_kbps) ||
      !isSafePositiveInteger(value.camera.gop) || !Array.isArray(value.models)) {
    return invalid();
  }

  const profileIds = new Set(capabilities.camera_profiles.map(({ id }) => id));
  if (!profileIds.has(value.camera.profile_id) ||
      value.camera.bitrate_kbps < capabilities.bitrate_kbps.minimum ||
      value.camera.bitrate_kbps > capabilities.bitrate_kbps.maximum ||
      value.camera.gop < capabilities.gop.minimum ||
      value.camera.gop > capabilities.gop.maximum ||
      value.models.length !== capabilities.models.length) {
    return invalid();
  }

  const models = value.models.map((model, index): ModelRuntimeSettings => {
    if (!hasExactKeys(model, ['id', 'enabled', 'confidence_threshold']) ||
        !isNonemptyString(model.id) || typeof model.enabled !== 'boolean' ||
        !isConfidence(model.confidence_threshold) ||
        model.id !== capabilities.models[index]?.id) {
      return invalid();
    }
    return {
      id: model.id,
      enabled: model.enabled,
      confidence_threshold: model.confidence_threshold,
    };
  });
  requireUniqueIds(models);
  return {
    camera: {
      profile_id: value.camera.profile_id,
      bitrate_kbps: value.camera.bitrate_kbps,
      gop: value.camera.gop,
    },
    sub_stream: parseSubStream(value.sub_stream, capabilities),
    osd: parseOsd(value.osd),
    models,
  };
}

function parseLastApply(value: unknown): LastApply {
  if (!hasExactKeys(value, ['status', 'code', 'restored']) ||
      typeof value.code !== 'string' || typeof value.restored !== 'boolean') {
    return invalid();
  }
  if ((value.status === 'never' || value.status === 'success') &&
      value.code === '' && value.restored === false) {
    return { status: value.status, code: '', restored: false };
  }
  if (value.status === 'failed' && value.code === 'E_SETTINGS_APPLY_FAILED') {
    return {
      status: 'failed',
      code: 'E_SETTINGS_APPLY_FAILED',
      restored: value.restored,
    };
  }
  return invalid();
}

function parseSnapshot(
  value: unknown,
  expectedKeys: readonly string[],
): RuntimeSettingsSnapshot {
  if (!hasExactKeys(value, expectedKeys) || value.schema_version !== 1 ||
      !isSafeNonnegativeInteger(value.revision) ||
      (value.state !== 'clean' && value.state !== 'pending' &&
       value.state !== 'applying' && value.state !== 'failed' &&
       value.state !== 'recovery_required')) {
    return invalid();
  }
  const capabilities = parseCapabilities(value.capabilities);
  const active = parseRuntimeSettings(value.active, capabilities);
  const pending = value.pending === null
    ? null
    : parseRuntimeSettings(value.pending, capabilities);
  if ((value.state === 'clean' && pending !== null) ||
      ((value.state === 'pending' || value.state === 'applying') && pending === null)) {
    return invalid();
  }
  return {
    schema_version: 1,
    revision: value.revision,
    state: value.state,
    capabilities,
    active,
    pending,
    last_apply: parseLastApply(value.last_apply),
  };
}

export function parseRuntimeSettingsSnapshot(value: unknown): RuntimeSettingsSnapshot {
  return parseSnapshot(value, snapshotKeys);
}

export function parseRuntimeSettingsApplyResponse(
  value: unknown,
): RuntimeSettingsApplyResponse {
  const keys = [...snapshotKeys, 'applied', 'restored'];
  const snapshot = parseSnapshot(value, keys);
  if (!isRecord(value) || value.applied !== true || value.restored !== false) {
    return invalid();
  }
  return { snapshot, applied: true, restored: false };
}

export function isRuntimeSettingsErrorCode(
  value: string,
): value is RuntimeSettingsErrorCode {
  return settingsErrorCodes.has(value as RuntimeSettingsErrorCode);
}
