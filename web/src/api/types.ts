export type SetupStatus =
  | {
      required: true;
      phase: 'administrator' | 'runtime_pending';
      tls: 'ready';
      peer_ip: string;
    }
  | { required: false };

export interface InitializeResult {
  required: false;
  runtime: 'running';
}

export interface Principal {
  username: string;
  role: UserRole;
}

export type UserRole = 'administrator' | 'viewer';

export interface LoginResult {
  role: UserRole;
  idle_expires_at_seconds: number;
}

export interface LogoutResult {
  logged_out: true;
}

export interface HealthStatus {
  status: string;
}

export interface CameraStatus {
  id: string;
  state: string;
  snapshot_available: boolean;
}

export interface MonitoringCamera extends CameraStatus {
  width: number;
  height: number;
}

export interface MonitoringCameraList {
  cameras: MonitoringCamera[];
}

export interface SelfPasswordChangeResult {
  password_changed: true;
  logged_out: true;
}

export interface AiModelStatus {
  id: string;
  kind: string;
  input_width: number;
  input_height: number;
  input_format: string;
  letterbox: boolean;
  output_name: string;
  confidence_threshold: number;
  labels: string;
}

export interface AiRunnerStatus {
  camera_id: string;
  model_id: string;
  model_kind: string;
  submitted_frames: number;
  processed_frames: number;
  dropped_frames: number;
  last_preprocess_ms: number;
  last_inference_ms: number;
  last_processed_sequence: number;
  last_error_code: string;
  last_error_message: string;
}

export interface AiStatus {
  enabled: boolean;
  backend: string;
  state: string;
  model_count: number;
  runner_count: number;
  reason: string;
  models: AiModelStatus[];
  runners: AiRunnerStatus[];
}

export interface RestartAiResult {
  status: 'restarted';
  ai?: AiStatus;
}

export interface RuntimeRestartResult {
  runtime: 'running';
}

export interface CameraInventory {
  cameras: CameraStatus[];
  ai: AiStatus;
}

export interface SecureMediaStatus {
  control_scheme: string;
  media_profile: string;
  keying: string;
  requires_tls_control_channel: boolean;
  per_media_key_zeroize_count?: number;
}

export interface StreamStatus {
  url: string;
  control_tls: boolean;
  media_srtp: boolean;
  secure_media: SecureMediaStatus;
}

export interface DetectionBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface DetectionKeypoint {
  name: string;
  x: number;
  y: number;
  confidence: number;
}

export interface Detection {
  class_id: number;
  label: string;
  confidence: number;
  box: DetectionBox;
  keypoints: DetectionKeypoint[];
}

export interface DetectionEvent {
  camera_id: string;
  model_id: string;
  model_kind: string;
  result_state: string;
  frame_sequence: number;
  frame_timestamp_ns: number;
  detections: Detection[];
}

export interface DetectionSnapshot {
  events: DetectionEvent[];
}

export type Parser<T> = (value: unknown) => T;

export interface CameraApiClient {
  getJson<T>(path: string, parser: Parser<T>, signal?: AbortSignal): Promise<T>;
  deleteJson<T>(path: string, parser: Parser<T>, signal?: AbortSignal): Promise<T>;
  putJson<B, T>(
    path: string,
    body: B,
    parser: Parser<T>,
    signal?: AbortSignal,
  ): Promise<T>;
  postJson<B, T>(
    path: string,
    body: B,
    parser: Parser<T>,
    signal?: AbortSignal,
  ): Promise<T>;
  getBlob(path: string, signal?: AbortSignal): Promise<Blob>;
  setUnauthorizedHandler(handler: (() => void) | null): void;
}
