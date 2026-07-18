import {
  expect,
  type Locator,
  type Page,
  type Request,
  test,
} from '@playwright/test';

import type { RuntimeSettingsSnapshot } from '../src/features/settings/contracts';
import type {
  ManagedUser,
  ManagementIp,
} from '../src/features/users/contracts';

const LIVE_MP4_BASE64 = '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';

const PRODUCTION_CSP = "default-src 'self'; img-src 'self' blob:; " +
  "object-src 'none'; media-src 'self' blob:; base-uri 'none'; frame-ancestors 'none'";

const operationalPayloads: Record<string, unknown> = {
  '/api/v1/health': { status: 'ok' },
  '/api/v1/cameras': {
    cameras: [{ id: 'imx708', state: 'streaming', snapshot_available: true }],
    ai: {
      enabled: true,
      backend: 'hailort',
      state: 'running',
      model_count: 1,
      runner_count: 1,
      reason: 'Hailo runtime ready',
      models: [{
        id: 'yolov8',
        kind: 'object_detection',
        input_width: 640,
        input_height: 640,
        input_format: 'RGB',
        letterbox: true,
        output_name: 'detections',
        confidence_threshold: 0.5,
        labels: 'person, vehicle',
      }],
      runners: [{
        camera_id: 'imx708',
        model_id: 'yolov8',
        model_kind: 'object_detection',
        submitted_frames: 120,
        processed_frames: 119,
        dropped_frames: 1,
        last_preprocess_ms: 1.2,
        last_inference_ms: 3.4,
        last_processed_sequence: 120,
        last_error_code: '',
        last_error_message: '',
      }],
    },
  },
  '/api/v1/stream': {
    url: 'rtsps://camera.local:8555/imx708/main',
    control_tls: true,
    media_srtp: true,
    secure_media: {
      control_scheme: 'rtsps',
      media_profile: 'RTP/SAVP',
      keying: 'sdes',
      requires_tls_control_channel: true,
      per_media_key_zeroize_count: 7,
    },
  },
  '/api/v1/ai/detections': { events: [] },
};

const detectionSnapshot = {
  events: [{
    camera_id: 'imx708',
    model_id: 'yolov8',
    model_kind: 'object_detection',
    result_state: 'decoded',
    frame_sequence: 121,
    frame_timestamp_ns: 121000,
    detections: [{
      class_id: 0,
      label: 'person',
      confidence: 0.94,
      box: { x: 0.18, y: 0.15, width: 0.34, height: 0.62 },
      keypoints: [],
    }],
  }],
};

const monitoringPayload = {
  cameras: [{
    id: 'imx708', state: 'streaming', snapshot_available: true, width: 320, height: 180,
  }],
};

const SNAPSHOT_JPEG_BASE64 =
  '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////'
  + '2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAf/'
  + 'xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAF//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABBQJ//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwF//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwF//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQAGPwJ//8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPyF//9k=';

const administratorOnlyPaths = new Set([
  '/api/v1/health',
  '/api/v1/cameras',
  '/api/v1/stream',
  '/api/v1/runtime/restart',
  '/api/v1/settings/runtime',
  '/api/v1/settings/runtime/apply',
  '/api/v1/settings/runtime/discard',
  '/api/v1/security/users',
  '/api/v1/security/management-ips',
]);

const makeRuntimeSettingsSnapshot = (
  state: RuntimeSettingsSnapshot['state'] = 'clean',
): RuntimeSettingsSnapshot => ({
  schema_version: 1,
  revision: 1,
  state,
  capabilities: {
    camera_profiles: [
      { id: 'imx708-1080p50', width: 1920, height: 1080, fps: 50,
        label: '1080p / 50 fps' },
      { id: 'imx708-720p50', width: 1280, height: 720, fps: 50,
        label: '720p / 50 fps' },
    ],
    bitrate_kbps: { minimum: 500, maximum: 20_000 },
    gop: { minimum: 1, maximum: 300 },
    models: [
      { id: 'yolov8', kind: 'object_detection', input_width: 640,
        input_height: 640, input_format: 'RGB', letterbox: true,
        labels: 'person, vehicle' },
      { id: 'pose', kind: 'pose', input_width: 640,
        input_height: 640, input_format: 'RGB', letterbox: true,
        labels: 'pose17' },
    ],
  },
  active: {
    camera: { profile_id: 'imx708-1080p50', bitrate_kbps: 6_000, gop: 25 },
    models: [
      { id: 'yolov8', enabled: true, confidence_threshold: 0.5 },
      { id: 'pose', enabled: false, confidence_threshold: 0.5 },
    ],
  },
  pending: null,
  last_apply: { status: 'never', code: '', restored: false },
});

interface ApiMockOptions {
  setupRequired?: boolean;
  setupPhase?: 'administrator' | 'runtime_pending';
  authenticated?: boolean;
  role?: 'administrator' | 'viewer';
  username?: string;
  runtimeFailed?: boolean;
  settingsRevisionConflictOnce?: boolean;
  settingsApplyFailureOnce?: boolean;
  settingsRecoveryRequired?: boolean;
}

interface ApiMockControls {
  initializeRequests: Request[];
  runtimeRequests: Request[];
  runtimeRestartRequests: Request[];
  liveRequests: Request[];
  settingsRequests: Request[];
  passwordRequests: Request[];
  snapshotRequests: Request[];
  authMeRequests: Request[];
  userManagementRequests: Request[];
  unhandledPaths: string[];
  requestedAdministratorPaths: string[];
  emitDetection(): void;
}

async function installApiMocks(
  page: Page,
  options: ApiMockOptions = {},
): Promise<ApiMockControls> {
  let setupRequired = options.setupRequired ?? false;
  const setupPhase = options.setupPhase ?? 'administrator';
  let authenticated = options.authenticated ?? true;
  const role = options.role ?? 'administrator';
  let username = options.username ?? 'operator.one';
  let runtimeFailed = options.runtimeFailed ?? false;
  let settingsRevisionConflictOnce = options.settingsRevisionConflictOnce ?? false;
  let settingsApplyFailureOnce = options.settingsApplyFailureOnce ?? false;
  let runtimeSettings = makeRuntimeSettingsSnapshot(
    options.settingsRecoveryRequired ? 'recovery_required' : 'clean',
  );
  const managedUsers: ManagedUser[] = [{
    id: 1,
    username: 'operator.one',
    role: 'administrator',
    enabled: true,
    lock_until_seconds: null,
    created_at_seconds: 1_720_000_000,
    password_changed_at_seconds: 1_720_000_000,
    last_login_at_seconds: 1_720_000_100,
  }];
  const managementIps: ManagementIp[] = [{
    id: 1,
    address: '192.0.2.44',
    role: 'administrator',
    created_at_seconds: 1_720_000_000,
  }];
  let nextUserId = 2;
  let nextManagementIpId = 2;
  let emitDetection!: () => void;
  const detectionGate = new Promise<void>((resolve) => {
    emitDetection = resolve;
  });
  const initializeRequests: Request[] = [];
  const runtimeRequests: Request[] = [];
  const runtimeRestartRequests: Request[] = [];
  const liveRequests: Request[] = [];
  const settingsRequests: Request[] = [];
  const passwordRequests: Request[] = [];
  const snapshotRequests: Request[] = [];
  const authMeRequests: Request[] = [];
  const userManagementRequests: Request[] = [];
  const unhandledPaths: string[] = [];
  const requestedAdministratorPaths: string[] = [];

  await page.addInitScript((liveMp4Base64) => {
    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const response = await nativeFetch(input, init);
      const rawUrl = typeof input === 'string'
        ? input
        : input instanceof Request ? input.url : input.toString();
      const path = new URL(rawUrl, window.location.href).pathname;
      if (path !== '/api/v1/cameras/imx708/live.mp4' || !response.ok) {
        return response;
      }
      const bytes = Uint8Array.from(atob(liveMp4Base64),
        (value) => value.charCodeAt(0));
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
        },
      });
      return new Response(stream, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    };
  }, LIVE_MP4_BASE64);

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;

    if (administratorOnlyPaths.has(path)) {
      requestedAdministratorPaths.push(`${request.method()} ${path}`);
    }

    if (path === '/api/v1/setup/status' && request.method() === 'GET') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify(setupRequired
          ? { required: true, phase: setupPhase,
            tls: 'ready', peer_ip: '192.0.2.44' }
          : { required: false }),
      });
      return;
    }
    if (path === '/api/v1/setup/initialize' && request.method() === 'POST') {
      initializeRequests.push(request);
      setupRequired = false;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ required: false, runtime: 'running' }),
      });
      return;
    }
    if (path === '/api/v1/setup/runtime' && request.method() === 'POST') {
      runtimeRequests.push(request);
      setupRequired = false;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ required: false, runtime: 'running' }),
      });
      return;
    }
    if (path === '/api/v1/runtime/restart' && request.method() === 'POST') {
      runtimeRestartRequests.push(request);
      runtimeFailed = false;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ runtime: 'running' }),
      });
      return;
    }
    if (path === '/api/v1/auth/me' && request.method() === 'GET') {
      authMeRequests.push(request);
      await route.fulfill(authenticated ? {
        contentType: 'application/json',
        body: JSON.stringify({ username, role }),
      } : {
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'E_AUTHENTICATION_REQUIRED' }),
      });
      return;
    }
    if (path === '/api/v1/auth/login' && request.method() === 'POST') {
      const body = request.postDataJSON() as { username?: unknown };
      if (typeof body.username === 'string' && body.username.length > 0) {
        username = body.username;
      }
      authenticated = true;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ role, idle_expires_at_seconds: 300 }),
      });
      return;
    }
    if (path === '/api/v1/auth/password' && request.method() === 'PUT') {
      passwordRequests.push(request);
      authenticated = false;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ password_changed: true, logged_out: true }),
      });
      return;
    }
    if (path === '/api/v1/auth/logout' && request.method() === 'POST') {
      authenticated = false;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ logged_out: true }),
      });
      return;
    }
    if (path === '/api/v1/security/users' && request.method() === 'GET') {
      userManagementRequests.push(request);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ users: managedUsers }),
      });
      return;
    }
    if (path === '/api/v1/security/users' && request.method() === 'POST') {
      userManagementRequests.push(request);
      const body = request.postDataJSON() as { username: string; password: string };
      const createdUser: ManagedUser = {
        id: nextUserId,
        username: body.username,
        role: 'viewer',
        enabled: true,
        lock_until_seconds: null,
        created_at_seconds: 1_720_000_200,
        password_changed_at_seconds: 1_720_000_200,
        last_login_at_seconds: null,
      };
      nextUserId += 1;
      managedUsers.push(createdUser);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ user: createdUser }),
      });
      return;
    }
    const enabledMatch = path.match(
      /^\/api\/v1\/security\/users\/([1-9]\d*)\/enabled$/,
    );
    if (request.method() === 'PUT' && enabledMatch !== null) {
      userManagementRequests.push(request);
      requestedAdministratorPaths.push(`${request.method()} ${path}`);
      const body = request.postDataJSON() as { enabled: boolean };
      const user = managedUsers.find((entry) => entry.id === Number(enabledMatch[1]));
      if (user !== undefined) {
        user.enabled = body.enabled;
      }
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ updated: true }),
      });
      return;
    }
    const passwordMatch = path.match(
      /^\/api\/v1\/security\/users\/([1-9]\d*)\/password$/,
    );
    if (request.method() === 'PUT' && passwordMatch !== null) {
      userManagementRequests.push(request);
      requestedAdministratorPaths.push(`${request.method()} ${path}`);
      const user = managedUsers.find((entry) => entry.id === Number(passwordMatch[1]));
      if (user !== undefined) {
        user.password_changed_at_seconds = 1_720_000_300;
      }
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ password_reset: true }),
      });
      return;
    }
    const userMatch = path.match(/^\/api\/v1\/security\/users\/([1-9]\d*)$/);
    if (request.method() === 'DELETE' && userMatch !== null &&
        request.postData() === null) {
      userManagementRequests.push(request);
      requestedAdministratorPaths.push(`${request.method()} ${path}`);
      const userIndex = managedUsers.findIndex(
        (entry) => entry.id === Number(userMatch[1]),
      );
      if (userIndex !== -1) {
        managedUsers.splice(userIndex, 1);
      }
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ deleted: true }),
      });
      return;
    }
    if (path === '/api/v1/security/management-ips' && request.method() === 'GET') {
      userManagementRequests.push(request);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          management_ips: managementIps,
          current_peer_ip: '192.0.2.44',
        }),
      });
      return;
    }
    const managementIpRoleMatch = path.match(
      /^\/api\/v1\/security\/management-ips\/(administrator|viewer)$/,
    );
    if (request.method() === 'POST' && managementIpRoleMatch !== null) {
      userManagementRequests.push(request);
      requestedAdministratorPaths.push(`${request.method()} ${path}`);
      const body = request.postDataJSON() as { address: string };
      const createdIp: ManagementIp = {
        id: nextManagementIpId,
        address: body.address,
        role: managementIpRoleMatch[1] as ManagementIp['role'],
        created_at_seconds: 1_720_000_200,
      };
      nextManagementIpId += 1;
      managementIps.push(createdIp);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ management_ip: createdIp }),
      });
      return;
    }
    const managementIpMatch = path.match(
      /^\/api\/v1\/security\/management-ips\/(administrator|viewer)\/([1-9]\d*)$/,
    );
    if (request.method() === 'PUT' && managementIpMatch !== null) {
      userManagementRequests.push(request);
      requestedAdministratorPaths.push(`${request.method()} ${path}`);
      const body = request.postDataJSON() as { address: string };
      const entry = managementIps.find((candidate) =>
        candidate.role === managementIpMatch[1] &&
        candidate.id === Number(managementIpMatch[2]));
      if (entry !== undefined) {
        entry.address = body.address;
      }
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ updated: true }),
      });
      return;
    }
    if (request.method() === 'DELETE' && managementIpMatch !== null &&
        request.postData() === null) {
      userManagementRequests.push(request);
      requestedAdministratorPaths.push(`${request.method()} ${path}`);
      const entryIndex = managementIps.findIndex((candidate) =>
        candidate.role === managementIpMatch[1] &&
        candidate.id === Number(managementIpMatch[2]));
      if (entryIndex !== -1) {
        managementIps.splice(entryIndex, 1);
      }
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ deleted: true }),
      });
      return;
    }
    if (path === '/api/v1/settings/runtime' && request.method() === 'GET') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify(runtimeSettings),
      });
      return;
    }
    if (path === '/api/v1/settings/runtime' && request.method() === 'PUT') {
      settingsRequests.push(request);
      const command = request.postDataJSON() as {
        expected_revision: number;
        settings: RuntimeSettingsSnapshot['active'];
      };
      if (settingsRevisionConflictOnce) {
        settingsRevisionConflictOnce = false;
        runtimeSettings = {
          ...runtimeSettings,
          revision: runtimeSettings.revision + 1,
        };
        await route.fulfill({
          status: 409,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'E_SETTINGS_REVISION_CONFLICT' }),
        });
        return;
      }
      if (command.expected_revision !== runtimeSettings.revision) {
        await route.fulfill({
          status: 409,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'E_SETTINGS_REVISION_CONFLICT' }),
        });
        return;
      }
      runtimeSettings = {
        ...runtimeSettings,
        revision: runtimeSettings.revision + 1,
        state: 'pending',
        pending: structuredClone(command.settings),
      };
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify(runtimeSettings),
      });
      return;
    }
    if (path === '/api/v1/settings/runtime/apply' && request.method() === 'POST') {
      settingsRequests.push(request);
      const command = request.postDataJSON() as { expected_revision: number };
      if (command.expected_revision !== runtimeSettings.revision) {
        await route.fulfill({
          status: 409,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'E_SETTINGS_REVISION_CONFLICT' }),
        });
        return;
      }
      if (runtimeSettings.pending === null) {
        await route.fulfill({
          status: 409,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'E_SETTINGS_NO_PENDING' }),
        });
        return;
      }
      if (settingsApplyFailureOnce) {
        settingsApplyFailureOnce = false;
        runtimeSettings = {
          ...runtimeSettings,
          revision: runtimeSettings.revision + 1,
          state: 'failed',
          last_apply: {
            status: 'failed',
            code: 'E_SETTINGS_APPLY_FAILED',
            restored: true,
          },
        };
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'E_SETTINGS_APPLY_FAILED' }),
        });
        return;
      }
      runtimeSettings = {
        ...runtimeSettings,
        revision: runtimeSettings.revision + 1,
        state: 'clean',
        active: structuredClone(runtimeSettings.pending),
        pending: null,
        last_apply: { status: 'success', code: '', restored: false },
      };
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ...runtimeSettings,
          applied: true,
          restored: false,
        }),
      });
      return;
    }
    if (path === '/api/v1/settings/runtime/discard' && request.method() === 'POST') {
      settingsRequests.push(request);
      const command = request.postDataJSON() as { expected_revision: number };
      if (command.expected_revision !== runtimeSettings.revision) {
        await route.fulfill({
          status: 409,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'E_SETTINGS_REVISION_CONFLICT' }),
        });
        return;
      }
      if (runtimeSettings.pending === null) {
        await route.fulfill({
          status: 409,
          contentType: 'application/json',
          body: JSON.stringify({ code: 'E_SETTINGS_NO_PENDING' }),
        });
        return;
      }
      runtimeSettings = {
        ...runtimeSettings,
        revision: runtimeSettings.revision + 1,
        state: 'clean',
        pending: null,
      };
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify(runtimeSettings),
      });
      return;
    }
    if (path === '/api/v1/monitoring/cameras' && request.method() === 'GET') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify(monitoringPayload),
      });
      return;
    }
    if (path === '/api/v1/cameras/imx708/snapshot.jpg' && request.method() === 'GET') {
      snapshotRequests.push(request);
      await route.fulfill({
        contentType: 'image/jpeg',
        body: Buffer.from(SNAPSHOT_JPEG_BASE64, 'base64'),
      });
      return;
    }
    if (path === '/api/v1/cameras/imx708/live.mp4' && request.method() === 'GET') {
      liveRequests.push(request);
      await route.fulfill({
        contentType: 'video/mp4',
        body: Buffer.from(LIVE_MP4_BASE64, 'base64'),
      });
      return;
    }
    if (path === '/api/v1/ai/detections/stream' && request.method() === 'GET') {
      await detectionGate;
      await route.fulfill({
        status: 200,
        contentType: 'text/event-stream',
        headers: { 'Cache-Control': 'no-cache' },
        body: `retry: 600000\nevent: detections\ndata: ${JSON.stringify(detectionSnapshot)}\n\n`,
      });
      return;
    }
    if (request.method() === 'GET' && path === '/api/v1/cameras') {
      const inventory = operationalPayloads[path] as {
        cameras: Array<Record<string, unknown>>;
        ai: unknown;
      };
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ...inventory,
          cameras: inventory.cameras.map((camera) => ({
            ...camera,
            state: runtimeFailed ? 'error' : camera.state,
            snapshot_available: runtimeFailed ? false : camera.snapshot_available,
          })),
        }),
      });
      return;
    }
    if (request.method() === 'GET' && path in operationalPayloads) {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify(operationalPayloads[path]),
      });
      return;
    }

    unhandledPaths.push(`${request.method()} ${path}`);
    await route.fulfill({
      status: 500,
      contentType: 'application/json',
      body: JSON.stringify({ code: 'E_UNMOCKED_TEST_ROUTE' }),
    });
  });

  return { initializeRequests, runtimeRequests, runtimeRestartRequests,
    liveRequests, settingsRequests, passwordRequests, snapshotRequests, authMeRequests,
    userManagementRequests, unhandledPaths, requestedAdministratorPaths, emitDetection };
}

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate(() => ({
    document: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
  }))).toEqual({ document: 0, body: 0 });
}

async function expectNoOverlap(a: Locator, b: Locator): Promise<void> {
  const [first, second] = await Promise.all([a.boundingBox(), b.boundingBox()]);
  expect(first).not.toBeNull();
  expect(second).not.toBeNull();
  const horizontal = Math.min(first!.x + first!.width, second!.x + second!.width) -
    Math.max(first!.x, second!.x);
  const vertical = Math.min(first!.y + first!.height, second!.y + second!.height) -
    Math.max(first!.y, second!.y);
  expect(Math.min(horizontal, vertical)).toBeLessThanOrEqual(0);
}

async function expectDialogFitsViewport(
  page: Page,
  dialog: Locator,
  viewport: { width: number; height: number },
): Promise<void> {
  const box = await dialog.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
  expect(box!.y).toBeGreaterThanOrEqual(0);
  expect(box!.y + box!.height).toBeLessThanOrEqual(viewport.height);
  expect(await dialog.evaluate((element) =>
    element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  const verticalFit = await dialog.evaluate((element) => ({
    scrollHeight: element.scrollHeight,
    clientHeight: element.clientHeight,
  }));
  expect(verticalFit.scrollHeight).toBeLessThanOrEqual(verticalFit.clientHeight);
  expect(await dialog.locator('input, select, button').evaluateAll((elements) =>
    elements.every((element) => element.scrollWidth <= element.clientWidth + 1)))
    .toBe(true);

  const title = dialog.getByRole('heading');
  const close = dialog.getByRole('button', { name: /^Close / });
  await expectNoOverlap(title, close);
  const stackedRegions = dialog.locator('.field, .user-management-dialog-actions');
  for (let index = 0; index + 1 < await stackedRegions.count(); index += 1) {
    await expectNoOverlap(stackedRegions.nth(index), stackedRegions.nth(index + 1));
  }
  await expectNoHorizontalOverflow(page);
}

async function canvasChecksum(canvas: Locator): Promise<number> {
  return canvas.evaluate((element: HTMLCanvasElement) => {
    const context = element.getContext('2d');
    if (context === null || element.width === 0 || element.height === 0) {
      return 0;
    }
    const pixels = context.getImageData(0, 0, element.width, element.height).data;
    let checksum = 0;
    for (let index = 0; index < pixels.length; index += 4) {
      checksum += pixels[index] + pixels[index + 1] + pixels[index + 2] + pixels[index + 3];
    }
    return checksum;
  });
}

test('first boot creates an administrator then shows login', async ({ page }) => {
  const api = await installApiMocks(page, {
    setupRequired: true,
    authenticated: false,
  });

  await page.goto('/#/setup');
  const panel = page.getByRole('region', { name: 'Create administrator' });
  await expect(panel).toBeVisible();
  await expect(panel).toHaveClass(/auth-panel/);
  await expect(panel.locator('xpath=..')).toHaveClass(/auth-surface/);
  await expect(panel.locator('.brand-mark')).toHaveText('CF');
  await expect(panel.locator('.field')).toHaveCount(4);
  await expect(page.getByRole('button', { name: 'Initialize camera' }))
    .toHaveClass(/primary-button/);
  const desktopPanel = await panel.boundingBox();
  expect(desktopPanel).not.toBeNull();
  expect(desktopPanel!.width).toBeLessThanOrEqual(390);

  await page.setViewportSize({ width: 390, height: 844 });
  await expectNoHorizontalOverflow(page);
  const mobilePanel = await panel.boundingBox();
  expect(mobilePanel).not.toBeNull();
  expect(mobilePanel!.width).toBeLessThanOrEqual(350);
  await page.getByLabel('Username').fill('operator.one');
  await page.getByLabel('Password', { exact: true }).fill('Short!9A');
  await page.getByLabel('Confirm password').fill('Short!9A');
  await page.getByRole('button', { name: 'Initialize camera' }).click();

  const passwordError = page.getByText('Password must be 9 to 128 characters.');
  await expect(passwordError).toBeVisible();
  await expect(passwordError).toHaveClass(/form-error/);
  expect(api.initializeRequests).toHaveLength(0);
  await page.getByLabel('Password', { exact: true }).fill('NorthStar!9');
  await page.getByLabel('Confirm password').fill('NorthStar!9');
  await page.getByRole('button', { name: 'Initialize camera' }).click();

  await expect(page.getByRole('heading', { name: 'Camera login' })).toBeVisible();
  expect(api.initializeRequests).toHaveLength(1);
  expect(api.initializeRequests[0].postDataJSON()).toEqual({
    username: 'operator.one',
    password: 'NorthStar!9',
    peer_ip: '192.0.2.44',
  });
  expect(api.initializeRequests[0].headers()['content-type']).toBe('application/json');
  expect(api.initializeRequests[0].headers()['x-camera-request']).toBe('management');
  expect(api.unhandledPaths).toEqual([]);
});

test('runtime recovery only starts from its explicit button and remains bounded', async ({ page }) => {
  const api = await installApiMocks(page, {
    setupRequired: true,
    setupPhase: 'runtime_pending',
    authenticated: false,
  });

  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/#/setup');

  const panel = page.getByRole('region', { name: 'Start camera runtime' });
  await expect(panel).toBeVisible();
  const peerInput = page.getByLabel('Management peer address');
  const startButton = page.getByRole('button', { name: 'Start runtime' });
  await expect(panel.locator('form')).toHaveCount(0);
  await expect(panel.locator('.auth-form')).toHaveCount(1);
  await expect(startButton).toHaveAttribute('type', 'button');
  await expectNoHorizontalOverflow(page);
  const desktopPanel = await panel.boundingBox();
  expect(desktopPanel).not.toBeNull();
  expect(desktopPanel!.x).toBeGreaterThanOrEqual(0);
  expect(desktopPanel!.x + desktopPanel!.width).toBeLessThanOrEqual(1440);
  expect(desktopPanel!.y).toBeGreaterThanOrEqual(0);
  expect(desktopPanel!.y + desktopPanel!.height).toBeLessThanOrEqual(1000);
  expect(desktopPanel!.width).toBeLessThanOrEqual(390);

  await page.setViewportSize({ width: 390, height: 844 });
  await expectNoHorizontalOverflow(page);
  const mobilePanel = await panel.boundingBox();
  expect(mobilePanel).not.toBeNull();
  expect(mobilePanel!.x).toBeGreaterThanOrEqual(0);
  expect(mobilePanel!.x + mobilePanel!.width).toBeLessThanOrEqual(390);
  expect(mobilePanel!.y).toBeGreaterThanOrEqual(0);
  expect(mobilePanel!.y + mobilePanel!.height).toBeLessThanOrEqual(844);
  expect(mobilePanel!.width).toBeLessThanOrEqual(350);
  await peerInput.focus();
  await page.keyboard.press('Enter');
  await page.waitForTimeout(100);
  expect(api.runtimeRequests).toHaveLength(0);
  await startButton.click();
  await expect.poll(() => api.runtimeRequests.length).toBe(1);
  expect(api.unhandledPaths).toEqual([]);
});

test('authenticated desktop dashboard renders media, overlay, and stable layout', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  const api = await installApiMocks(page);

  const navigation = await page.goto('/#/dashboard');
  expect(navigation?.headers()['content-security-policy']).toBe(PRODUCTION_CSP);
  await expect(page.locator('[style]')).toHaveCount(0);

  const panelHeadings = [
    'Camera preview',
    'System and cameras',
    'Stream connection',
    'Hailo AI runtime',
  ];
  for (const heading of panelHeadings) {
    await expect(page.getByRole('heading', { name: heading })).toBeVisible();
  }
  await expect(page.getByText(
    'Frame 120 / preprocess 1.2 ms / inference 3.4 ms',
  )).toBeVisible();
  for (const value of ['RTSPS / TLS', 'SRTP', 'RTP/SAVP', 'sdes']) {
    await expect(page.getByText(value, { exact: true })).toBeVisible();
  }
  expect(await page.locator('.status-value').evaluateAll((elements) =>
    elements.every((element) =>
      element.scrollWidth <= element.clientWidth + 1 &&
      element.scrollHeight <= element.clientHeight + 1))).toBe(true);

  const video = page.locator('video[aria-label="imx708 camera preview"]');
  await expect(video).toBeVisible();
  await expect.poll(() => video.evaluate((element: HTMLVideoElement) => ({
    readyState: element.readyState,
    width: element.videoWidth,
    height: element.videoHeight,
  }))).toEqual({ readyState: 4, width: 320, height: 180 });
  expect(api.liveRequests).toHaveLength(1);
  expect(new URL(api.liveRequests[0].url()).pathname)
    .toBe('/api/v1/cameras/imx708/live.mp4');
  expect(new URL(api.liveRequests[0].url()).search).toBe('?generation=1');
  const reconnect = page.getByRole('button', { name: 'Reconnect preview' });
  await expect(reconnect).toBeVisible();

  const canvas = page.locator('canvas.detection-overlay');
  await expect(canvas).toBeVisible();
  await expect.poll(() => canvas.evaluate((element: HTMLCanvasElement) =>
    element.width > 0 && element.height > 0)).toBe(true);
  const beforeDetection = await canvasChecksum(canvas);
  expect(beforeDetection).toBe(0);
  api.emitDetection();
  await expect.poll(() => canvasChecksum(canvas)).toBeGreaterThan(beforeDetection);

  await page.getByRole('link', { name: 'Cameras' }).click();
  await expect(page.getByRole('heading', { name: 'Cameras', exact: true })).toBeVisible();
  await expect(video).toBeVisible();
  await page.getByRole('link', { name: 'Dashboard' }).click();
  await expect(page.getByRole('heading', { name: 'Operational dashboard' })).toBeVisible();
  await expect(video).toBeVisible();
  await expect(reconnect).toBeVisible();

  await expectNoHorizontalOverflow(page);
  const header = page.locator('.topbar');
  const sidebar = page.locator('.sidebar');
  const previewHeading = page.getByRole('heading', { name: 'Camera preview' }).locator('..');
  const cameraSelect = page.getByRole('combobox', { name: 'Camera' });
  const preview = page.getByRole('heading', { name: 'Camera preview' }).locator('..').locator('..');
  const ai = page.getByRole('heading', { name: 'Hailo AI runtime' }).locator('..').locator('..');
  await expectNoOverlap(header, sidebar);
  await expectNoOverlap(header, preview);
  await expectNoOverlap(header, ai);
  await expectNoOverlap(sidebar, preview);
  await expectNoOverlap(sidebar, ai);
  await expectNoOverlap(preview, ai);
  await expectNoOverlap(header, reconnect);
  await expectNoOverlap(sidebar, reconnect);
  await expectNoOverlap(previewHeading, cameraSelect);
  await expectNoOverlap(previewHeading, reconnect);
  await expectNoOverlap(cameraSelect, reconnect);

  await page.screenshot({
    path: testInfo.outputPath('desktop-dashboard.png'),
    fullPage: true,
  });
  expect(api.unhandledPaths).toEqual([]);
});

test('authenticated dashboard explicitly recovers a failed camera runtime', async ({ page }) => {
  const api = await installApiMocks(page, { runtimeFailed: true });

  await page.goto('/#/dashboard');
  await expect(page.getByText('error', { exact: true })).toBeVisible();
  const restart = page.getByRole('button', { name: 'Restart camera runtime' });
  await expect(restart).toBeVisible();
  await restart.click();

  await expect.poll(() => api.runtimeRestartRequests.length).toBe(1);
  expect(api.runtimeRestartRequests[0].postDataJSON()).toEqual({});
  expect(api.runtimeRestartRequests[0].headers()['x-camera-request'])
    .toBe('management');
  await expect(page.getByText('streaming', { exact: true })).toBeVisible();
  await expect(restart).toBeHidden();
  expect(api.unhandledPaths).toEqual([]);
});

test('mobile dashboard drawer is modal, keyboard dismissible, and unclipped', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const api = await installApiMocks(page);

  await page.goto('/#/dashboard');
  await expect(page.getByRole('heading', { name: 'Operational dashboard' })).toBeVisible();
  api.emitDetection();
  await expectNoHorizontalOverflow(page);
  await page.screenshot({ path: testInfo.outputPath('mobile-dashboard.png') });

  const trigger = page.getByRole('button', { name: 'Open navigation' });
  await trigger.click();
  const drawer = page.getByRole('dialog', { name: 'Navigation' });
  await expect(drawer).toBeVisible();
  await expect(drawer).toHaveAttribute('aria-modal', 'true');
  await expect(page.getByRole('button', { name: 'Close navigation' })).toBeFocused();
  for (const name of ['Dashboard', 'Cameras', 'AI', 'System']) {
    await expect(drawer.getByRole('link', { name })).toBeVisible();
  }

  const drawerBox = await drawer.boundingBox();
  expect(drawerBox).not.toBeNull();
  expect(drawerBox!.x).toBeGreaterThanOrEqual(0);
  expect(drawerBox!.x + drawerBox!.width).toBeLessThanOrEqual(390);
  expect(drawerBox!.y).toBeGreaterThanOrEqual(0);
  expect(drawerBox!.y + drawerBox!.height).toBeLessThanOrEqual(844);
  expect(await drawer.locator('button, a').evaluateAll((elements) =>
    elements.every((element) =>
      element.scrollWidth <= element.clientWidth + 1 &&
      element.scrollHeight <= element.clientHeight + 1))).toBe(true);
  await expectNoHorizontalOverflow(page);
  await page.screenshot({ path: testInfo.outputPath('mobile-drawer.png') });

  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  await expect(trigger).toBeFocused();

  await trigger.click();
  await page.getByRole('button', { name: 'Close navigation' }).click();
  await expect(drawer).toBeHidden();
  await expect(trigger).toBeFocused();

  await trigger.click();
  await drawer.getByRole('link', { name: 'AI' }).click();
  await expect(drawer).toBeHidden();
  await expect(page.getByRole('heading', { name: 'AI inference' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Hailo AI runtime' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'System and cameras' })).toBeHidden();
  await expect(page.locator('video[aria-label="imx708 camera preview"]')).toBeVisible();
  const reconnect = page.getByRole('button', { name: 'Reconnect preview' });
  await expect(reconnect).toBeVisible();
  await expectNoHorizontalOverflow(page);

  const header = page.locator('.topbar');
  const preview = page.getByRole('heading', { name: 'Camera preview' }).locator('..').locator('..');
  const ai = page.getByRole('heading', { name: 'Hailo AI runtime' }).locator('..').locator('..');
  await expectNoOverlap(header, preview);
  await expectNoOverlap(header, ai);
  await expectNoOverlap(preview, ai);
  await expectNoOverlap(header, reconnect);
  expect(api.unhandledPaths).toEqual([]);
});

test('desktop users and access completes the administrator lifecycle', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  const api = await installApiMocks(page);

  await page.goto('/#/users');
  await expect(page.getByRole('heading', { name: 'Users & access' })).toBeVisible();
  const accountsTab = page.getByRole('tab', { name: 'Accounts' });
  const accessIpsTab = page.getByRole('tab', { name: 'Access IPs' });
  await expect(accountsTab).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('row').filter({ hasText: 'operator.one' })).toBeVisible();

  await accessIpsTab.click();
  const protectedAddress = page.getByRole('row').filter({ hasText: '192.0.2.44' });
  await expect(page.getByRole('row').filter({ hasText: 'Administrator' })).toHaveCount(1);
  await expect(protectedAddress.getByText('Current connection', { exact: true })).toBeVisible();
  await expect(protectedAddress.getByRole('button', { name: 'Edit 192.0.2.44' }))
    .toBeDisabled();
  await expect(protectedAddress.getByRole('button', { name: 'Delete 192.0.2.44' }))
    .toBeDisabled();

  await accountsTab.click();
  await page.getByRole('button', { name: 'Add viewer' }).click();
  const addViewerDialog = page.getByRole('dialog', { name: 'Add viewer' });
  await addViewerDialog.getByLabel('Username').fill('viewer.one');
  await addViewerDialog.getByLabel('Password', { exact: true }).fill('ViewerPass9!');
  await addViewerDialog.getByLabel('Confirm password').fill('ViewerPass9!');
  await addViewerDialog.getByRole('button', { name: 'Create viewer' }).click();

  const viewerRow = page.getByRole('row').filter({ hasText: 'viewer.one' });
  await expect(viewerRow).toBeVisible();
  const createViewerRequest = api.userManagementRequests.find((request) =>
    request.method() === 'POST' &&
    new URL(request.url()).pathname === '/api/v1/security/users');
  expect(createViewerRequest).toBeDefined();
  expect(createViewerRequest!.postDataJSON()).toEqual({
    username: 'viewer.one',
    password: 'ViewerPass9!',
  });

  await viewerRow.getByRole('switch', { name: 'Disable viewer.one' }).click();
  const disableDialog = page.getByRole('dialog', { name: 'Disable viewer' });
  await expect(disableDialog).toContainText(
    "Disable viewer.one? The viewer's active session ends immediately.",
  );
  await disableDialog.getByRole('button', { name: 'Disable viewer', exact: true }).click();
  await expect(viewerRow.getByText('Disabled', { exact: true })).toBeVisible();
  const disableRequest = api.userManagementRequests.find((request) =>
    request.method() === 'PUT' &&
    new URL(request.url()).pathname === '/api/v1/security/users/2/enabled');
  expect(disableRequest?.postDataJSON()).toEqual({ enabled: false });

  await viewerRow.getByRole('button', { name: 'Reset password for viewer.one' }).click();
  const resetDialog = page.getByRole('dialog', { name: 'Reset viewer password' });
  await expect(resetDialog).toContainText('viewer.one');
  await expect(resetDialog).toContainText(
    "The viewer's active session may end immediately.",
  );
  await resetDialog.getByLabel('New password', { exact: true }).fill('ViewerPass10!');
  await resetDialog.getByLabel('Confirm new password').fill('ViewerPass10!');
  await resetDialog.getByRole('button', { name: 'Reset password' }).click();
  await expect(resetDialog).toBeHidden();
  const resetRequest = api.userManagementRequests.find((request) =>
    request.method() === 'PUT' &&
    new URL(request.url()).pathname === '/api/v1/security/users/2/password');
  expect(resetRequest).toBeDefined();
  expect(resetRequest!.postDataJSON()).toEqual({ password: 'ViewerPass10!' });

  await page.screenshot({
    path: testInfo.outputPath('desktop-users-access.png'),
    fullPage: true,
  });

  await accessIpsTab.click();
  await page.getByRole('button', { name: 'Add access IP' }).click();
  const addAccessIpDialog = page.getByRole('dialog', { name: 'Add access IP' });
  await addAccessIpDialog.getByLabel('Role').selectOption('viewer');
  await addAccessIpDialog.getByLabel('Address').fill('2001:db8::20');
  await addAccessIpDialog.getByRole('button', { name: 'Add access IP', exact: true }).click();

  const viewerIpRow = page.getByRole('row').filter({ hasText: '2001:db8::20' });
  await expect(viewerIpRow).toBeVisible();
  await expect(viewerIpRow.getByText('Viewer', { exact: true })).toBeVisible();
  const createIpRequest = api.userManagementRequests.find((request) =>
    request.method() === 'POST' &&
    new URL(request.url()).pathname === '/api/v1/security/management-ips/viewer');
  expect(createIpRequest).toBeDefined();
  expect(createIpRequest!.postDataJSON()).toEqual({ address: '2001:db8::20' });
  await viewerIpRow.getByRole('button', { name: 'Edit 2001:db8::20' }).click();
  const editAccessIpDialog = page.getByRole('dialog', { name: 'Edit access IP' });
  await editAccessIpDialog.getByLabel('Address').fill('2001:db8::21');
  await editAccessIpDialog.getByRole('button', { name: 'Save access IP' }).click();
  const updatedViewerIpRow = page.getByRole('row').filter({ hasText: '2001:db8::21' });
  await expect(updatedViewerIpRow).toBeVisible();
  const editIpRequest = api.userManagementRequests.find((request) =>
    request.method() === 'PUT' &&
    new URL(request.url()).pathname === '/api/v1/security/management-ips/viewer/2');
  expect(editIpRequest).toBeDefined();
  expect(editIpRequest!.postDataJSON()).toEqual({ address: '2001:db8::21' });

  await updatedViewerIpRow.getByRole('button', { name: 'Delete 2001:db8::21' }).click();
  const deleteAccessIpDialog = page.getByRole('alertdialog', { name: 'Delete access IP' });
  await deleteAccessIpDialog.getByRole('button', { name: 'Delete access IP', exact: true })
    .click();
  await expect(updatedViewerIpRow).toBeHidden();
  const deleteIpRequest = api.userManagementRequests.find((request) =>
    request.method() === 'DELETE' &&
    new URL(request.url()).pathname === '/api/v1/security/management-ips/viewer/2');
  expect(deleteIpRequest).toBeDefined();
  expect(deleteIpRequest!.postData()).toBeNull();

  await accountsTab.click();
  await viewerRow.getByRole('button', { name: 'Delete viewer.one' }).click();
  const deleteViewerDialog = page.getByRole('alertdialog', { name: 'Delete viewer' });
  await expect(deleteViewerDialog).toContainText('viewer.one');
  await expect(deleteViewerDialog).toContainText('This action cannot be undone.');
  await expect(deleteViewerDialog).toContainText(
    "The viewer's active session ends immediately.",
  );
  await deleteViewerDialog.getByRole('button', { name: 'Delete viewer', exact: true }).click();
  await expect(viewerRow).toBeHidden();
  const deleteViewerRequest = api.userManagementRequests.find((request) =>
    request.method() === 'DELETE' &&
    new URL(request.url()).pathname === '/api/v1/security/users/2');
  expect(deleteViewerRequest).toBeDefined();
  expect(deleteViewerRequest!.postData()).toBeNull();

  const mutationRequests = api.userManagementRequests
    .filter((request) => request.method() !== 'GET')
    .map((request) => `${request.method()} ${new URL(request.url()).pathname}`);
  expect(mutationRequests).toEqual([
    'POST /api/v1/security/users',
    'PUT /api/v1/security/users/2/enabled',
    'PUT /api/v1/security/users/2/password',
    'POST /api/v1/security/management-ips/viewer',
    'PUT /api/v1/security/management-ips/viewer/2',
    'DELETE /api/v1/security/management-ips/viewer/2',
    'DELETE /api/v1/security/users/2',
  ]);
  for (const path of mutationRequests) {
    expect(api.requestedAdministratorPaths).toContain(path);
  }
  expect(api.unhandledPaths).toEqual([]);
  await expectNoHorizontalOverflow(page);
});

test('mobile users and access dialogs remain bounded and restore focus', async ({
  page,
}, testInfo) => {
  const viewport = { width: 390, height: 844 };
  await page.setViewportSize(viewport);
  const api = await installApiMocks(page);

  await page.goto('/#/dashboard');
  await expect(page.getByRole('heading', { name: 'Operational dashboard' })).toBeVisible();
  await page.getByRole('button', { name: 'Open navigation' }).click();
  const drawer = page.getByRole('dialog', { name: 'Navigation' });
  await drawer.getByRole('link', { name: 'Users' }).click();
  await expect(drawer).toBeHidden();
  await expect(page.getByRole('heading', { name: 'Users & access' })).toBeVisible();

  const accountsTab = page.getByRole('tab', { name: 'Accounts' });
  const accessIpsTab = page.getByRole('tab', { name: 'Access IPs' });
  await expect(accountsTab).toHaveAttribute('aria-selected', 'true');
  await accessIpsTab.click();
  await expect(accessIpsTab).toHaveAttribute('aria-selected', 'true');
  await accountsTab.click();

  const addViewer = page.getByRole('button', { name: 'Add viewer' });
  await addViewer.click();
  const addViewerDialog = page.getByRole('dialog', { name: 'Add viewer' });
  await expectDialogFitsViewport(page, addViewerDialog, viewport);
  await page.keyboard.press('Escape');
  await expect(addViewerDialog).toBeHidden();
  await expect(addViewer).toBeFocused();

  await accessIpsTab.click();
  const addAccessIp = page.getByRole('button', { name: 'Add access IP' });
  await addAccessIp.click();
  const addAccessIpDialog = page.getByRole('dialog', { name: 'Add access IP' });
  await expectDialogFitsViewport(page, addAccessIpDialog, viewport);
  await page.screenshot({
    path: testInfo.outputPath('mobile-users-access.png'),
    fullPage: true,
  });
  await page.keyboard.press('Escape');
  await expect(addAccessIpDialog).toBeHidden();
  await expect(addAccessIp).toBeFocused();
  await expectNoOverlap(addAccessIp, page.getByRole('tablist', { name: 'Users and access' }));

  expect(api.unhandledPaths).toEqual([]);
  await expectNoHorizontalOverflow(page);
});

test('camera settings save explicitly, confirm apply, and remain responsive', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  const api = await installApiMocks(page);

  await page.goto('/#/cameras');
  await page.getByLabel('Capture profile').selectOption('imx708-720p50');
  await page.getByLabel('Bitrate').fill('7200');
  await page.getByRole('button', { name: 'Save changes' }).click();

  await expect(page.getByRole('status').filter({ hasText:
    'Runtime settings are waiting to be applied.' })).toBeVisible();
  await page.getByRole('button', { name: 'Apply pending' }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Apply runtime settings' });
  await expect(dialog).toContainText('Camera video and RTSP clients will reconnect briefly.');
  await dialog.getByRole('button', { name: 'Apply now' }).click();

  await expect(page.getByText('Active: 720p / 50 fps / 7200 kbps / GOP 25'))
    .toBeVisible();
  await expect(page.getByText('Runtime settings are waiting to be applied.'))
    .toHaveCount(0);
  expect(api.settingsRequests.map((request) => request.method()))
    .toEqual(['PUT', 'POST']);
  expect(api.settingsRequests[0].postDataJSON()).toMatchObject({
    expected_revision: 1,
    settings: {
      camera: { profile_id: 'imx708-720p50', bitrate_kbps: 7200, gop: 25 },
    },
  });

  await expectNoHorizontalOverflow(page);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: testInfo.outputPath('desktop-camera-settings.png'),
    fullPage: true,
  });
  for (const width of [1024, 768]) {
    await page.setViewportSize({ width, height: 900 });
    await expectNoHorizontalOverflow(page);
    await expect(page.getByLabel('Runtime settings actions')).toBeVisible();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await expectNoHorizontalOverflow(page);
  await expect(page.getByLabel('Runtime settings actions')).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: testInfo.outputPath('mobile-camera-settings.png'),
    fullPage: true,
  });
  expect(api.unhandledPaths).toEqual([]);
});

test('AI settings save and discard a pending model change', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  const api = await installApiMocks(page);

  await page.goto('/#/ai');
  await expectNoHorizontalOverflow(page);
  await page.screenshot({
    path: testInfo.outputPath('desktop-ai-settings.png'),
    fullPage: true,
  });
  await page.getByRole('switch', { name: 'pose enabled' }).check();
  await page.getByLabel('pose confidence value').fill('0.65');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText('Saved settings are waiting to be applied.'))
    .toBeVisible();
  await page.getByRole('button', { name: 'Discard pending' }).click();

  await expect(page.getByRole('switch', { name: 'pose enabled' })).not.toBeChecked();
  await expect(page.getByLabel('pose confidence value')).toHaveValue('0.5');
  expect(api.settingsRequests.map((request) => request.method()))
    .toEqual(['PUT', 'POST']);
  expect(new URL(api.settingsRequests[1].url()).pathname)
    .toBe('/api/v1/settings/runtime/discard');
  for (const width of [1024, 768]) {
    await page.setViewportSize({ width, height: 900 });
    await expectNoHorizontalOverflow(page);
    await expect(page.getByLabel('Runtime settings actions')).toBeVisible();
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await expectNoHorizontalOverflow(page);
  await expect(page.getByLabel('Runtime settings actions')).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: testInfo.outputPath('mobile-ai-settings.png'),
    fullPage: true,
  });
  expect(api.unhandledPaths).toEqual([]);
});

test('revision conflict preserves the local draft for an explicit retry', async ({ page }) => {
  const api = await installApiMocks(page, { settingsRevisionConflictOnce: true });

  await page.goto('/#/cameras');
  await page.getByLabel('Bitrate').fill('7100');
  await page.getByRole('button', { name: 'Save changes' }).click();

  await expect(page.getByRole('alert')).toContainText(
    'Settings changed on the device. Review and save your changes again.',
  );
  await expect(page.getByLabel('Bitrate')).toHaveValue('7100');
  await expect(page.getByRole('button', { name: 'Save changes' })).toBeEnabled();
  expect(api.settingsRequests).toHaveLength(1);
  expect(api.unhandledPaths).toEqual([]);
});

test('failed apply reports restored runtime and retains pending settings', async ({ page }) => {
  const api = await installApiMocks(page, { settingsApplyFailureOnce: true });

  await page.goto('/#/cameras');
  await page.getByLabel('Bitrate').fill('7300');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await page.getByRole('button', { name: 'Apply pending' }).click();
  await page.getByRole('button', { name: 'Apply now' }).click();

  await expect(page.getByRole('alert').filter({ hasText:
    'Settings could not be applied. The previous runtime was restored.' }))
    .toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply pending' })).toBeEnabled();
  await expect(page.getByText('Active: 1080p / 50 fps / 6000 kbps / GOP 25'))
    .toBeVisible();
  expect(api.unhandledPaths).toEqual([]);
});

test('recovery settings are replaced through save and apply', async ({ page }) => {
  const api = await installApiMocks(page, { settingsRecoveryRequired: true });

  await page.goto('/#/cameras');
  await expect(page.getByRole('status').filter({ hasText:
    'Runtime settings need recovery.' })).toBeVisible();
  await page.getByLabel('GOP interval').fill('30');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await page.getByRole('button', { name: 'Apply pending' }).click();
  await page.getByRole('button', { name: 'Apply now' }).click();

  await expect(page.getByText('Active: 1080p / 50 fps / 6000 kbps / GOP 30'))
    .toBeVisible();
  await expect(page.getByText('Runtime settings need recovery.')).toHaveCount(0);
  expect(api.unhandledPaths).toEqual([]);
});

test('logout remains available from the authenticated settings shell', async ({ page }) => {
  const api = await installApiMocks(page);

  await page.goto('/#/cameras');
  await page.getByRole('button', { name: 'Open user menu' }).click();
  await page.getByRole('button', { name: 'Sign out' }).click();

  await expect(page.getByRole('heading', { name: 'Camera login' })).toBeVisible();
  expect(api.unhandledPaths).toEqual([]);
});

test('viewer monitoring keeps the live shell least-privileged and responsive', async ({
  page,
}, testInfo) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  const api = await installApiMocks(page, {
    role: 'viewer',
    username: 'viewer.initial',
  });

  await page.goto('/#/dashboard');
  await expect(page).toHaveURL(/#\/monitor$/);
  await expect.poll(() => page.evaluate(() => window.history.state?.idx)).toBe(0);
  await expect(page.getByRole('heading', { name: 'Live monitoring' })).toBeVisible();
  const video = page.getByLabel('imx708 camera preview');
  const snapshot = page.getByRole('img', { name: 'imx708 camera snapshot' });
  await expect(video).toBeVisible();
  await expect(snapshot).toBeVisible();
  await expect(page.getByRole('link', { name: 'Live' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Dashboard' })).toHaveCount(0);
  await expect.poll(() => video.evaluate((element: HTMLVideoElement) => ({
    readyState: element.readyState,
    width: element.videoWidth,
    height: element.videoHeight,
  }))).toEqual({ readyState: 4, width: 320, height: 180 });

  const canvas = page.locator('canvas.detection-overlay');
  await expect(canvas).toBeVisible();
  await expect.poll(() => canvas.evaluate((element: HTMLCanvasElement) =>
    element.width > 0 && element.height > 0)).toBe(true);
  const beforeDetection = await canvasChecksum(canvas);
  api.emitDetection();
  await expect.poll(() => canvasChecksum(canvas)).toBeGreaterThan(beforeDetection);

  await expectNoHorizontalOverflow(page);
  const header = page.locator('.topbar');
  const livePreview = page.getByRole('heading', { name: 'Camera preview' }).locator('..').locator('..');
  const snapshotSection = page.getByRole('region', { name: 'Snapshot' });
  await expectNoOverlap(header, livePreview);
  await expectNoOverlap(header, snapshotSection);
  await expectNoOverlap(livePreview, snapshotSection);
  for (const surface of [video, snapshot]) {
    const box = await surface.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBeGreaterThan(0);
    expect(box!.height).toBeGreaterThan(0);
  }
  await page.screenshot({
    path: testInfo.outputPath('desktop-viewer-monitoring.png'),
    fullPage: true,
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await expectNoHorizontalOverflow(page);
  await expectNoOverlap(header, livePreview);
  await expectNoOverlap(header, snapshotSection);
  for (const surface of [video, snapshot]) {
    const box = await surface.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBeGreaterThan(0);
    expect(box!.height).toBeGreaterThan(0);
  }
  await page.screenshot({
    path: testInfo.outputPath('mobile-viewer-monitoring.png'),
    fullPage: true,
  });

  const navigationTrigger = page.getByRole('button', { name: 'Open navigation' });
  await navigationTrigger.click();
  const drawer = page.getByRole('dialog', { name: 'Navigation' });
  const closeNavigation = drawer.getByRole('button', { name: 'Close navigation' });
  await expect(drawer).toBeVisible();
  await expect(closeNavigation).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(drawer.getByRole('link', { name: 'Live' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(closeNavigation).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(navigationTrigger).toBeFocused();

  await page.getByRole('button', { name: 'Open user menu' }).click();
  await page.getByRole('button', { name: 'Change password' }).click();
  const dialog = page.getByRole('dialog', { name: 'Change password' });
  const currentPassword = dialog.getByLabel('Current password');
  await expect(currentPassword).toBeFocused();
  const closePasswordDialog = dialog.getByRole('button', {
    name: 'Close change password dialog',
  });
  await page.keyboard.press('Shift+Tab');
  await expect(closePasswordDialog).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(currentPassword).toBeFocused();
  await currentPassword.fill('NorthStar!9');
  await dialog.getByLabel('New password', { exact: true }).fill('Skyline!9');
  await dialog.getByLabel('Confirm new password', { exact: true }).fill('Skyline!9');
  await dialog.getByRole('button', { name: 'Change password', exact: true }).click();

  await expect(page.getByRole('heading', { name: 'Camera login' })).toBeVisible();
  expect(api.passwordRequests).toHaveLength(1);
  expect(api.passwordRequests[0].postDataJSON()).toEqual({
    current_password: 'NorthStar!9',
    replacement_password: 'Skyline!9',
  });
  expect(api.passwordRequests[0].headers()['x-camera-request']).toBe('management');
  expect(api.authMeRequests).toHaveLength(1);

  await page.getByLabel('Username').fill('viewer.reauthenticated');
  await page.getByLabel('Password', { exact: true }).fill('Skyline!9');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/#\/monitor$/);
  await expect(page.locator('.header-username')).toHaveText('viewer.reauthenticated');
  await page.getByRole('button', { name: 'Open user menu' }).click();
  await page.getByRole('button', { name: 'Change password' }).click();
  const reopenedDialog = page.getByRole('dialog', { name: 'Change password' });
  await expect(reopenedDialog.getByLabel('Current password')).toHaveValue('');
  await expect(reopenedDialog.getByLabel('New password', { exact: true })).toHaveValue('');
  await expect(reopenedDialog.getByLabel('Confirm new password', { exact: true })).toHaveValue('');

  expect(api.unhandledPaths).toEqual([]);
  expect(api.requestedAdministratorPaths).toEqual([]);
  expect(api.liveRequests).not.toHaveLength(0);
  expect(api.liveRequests.every((request) =>
    new URL(request.url()).pathname === '/api/v1/cameras/imx708/live.mp4')).toBe(true);
  expect(api.snapshotRequests).not.toHaveLength(0);
  expect(api.snapshotRequests.every((request) =>
    new URL(request.url()).pathname === '/api/v1/cameras/imx708/snapshot.jpg')).toBe(true);
});
