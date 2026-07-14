import {
  expect,
  type Locator,
  type Page,
  type Request,
  test,
} from '@playwright/test';

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

interface ApiMockOptions {
  setupRequired?: boolean;
  setupPhase?: 'administrator' | 'runtime_pending';
  authenticated?: boolean;
  runtimeFailed?: boolean;
}

interface ApiMockControls {
  initializeRequests: Request[];
  runtimeRequests: Request[];
  runtimeRestartRequests: Request[];
  liveRequests: Request[];
  unhandledPaths: string[];
  emitDetection(): void;
}

async function installApiMocks(
  page: Page,
  options: ApiMockOptions = {},
): Promise<ApiMockControls> {
  let setupRequired = options.setupRequired ?? false;
  const setupPhase = options.setupPhase ?? 'administrator';
  let authenticated = options.authenticated ?? true;
  let runtimeFailed = options.runtimeFailed ?? false;
  let emitDetection!: () => void;
  const detectionGate = new Promise<void>((resolve) => {
    emitDetection = resolve;
  });
  const initializeRequests: Request[] = [];
  const runtimeRequests: Request[] = [];
  const runtimeRestartRequests: Request[] = [];
  const liveRequests: Request[] = [];
  const unhandledPaths: string[] = [];

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
      await route.fulfill(authenticated ? {
        contentType: 'application/json',
        body: JSON.stringify({ username: 'operator.one', role: 'administrator' }),
      } : {
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ code: 'E_AUTHENTICATION_REQUIRED' }),
      });
      return;
    }
    if (path === '/api/v1/auth/login' && request.method() === 'POST') {
      authenticated = true;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ role: 'administrator', idle_expires_at_seconds: 300 }),
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
    liveRequests, unhandledPaths, emitDetection };
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

  await expect(page.getByRole('heading', { name: 'Administrator login' })).toBeVisible();
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
