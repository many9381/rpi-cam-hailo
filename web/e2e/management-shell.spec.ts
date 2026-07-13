import {
  expect,
  type Locator,
  type Page,
  type Request,
  test,
} from '@playwright/test';

const JPEG_BASE64 = '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';

const PRODUCTION_CSP = "default-src 'self'; img-src 'self' blob:; " +
  "object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

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
}

interface ApiMockControls {
  initializeRequests: Request[];
  runtimeRequests: Request[];
  previewRequests: Request[];
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
  let emitDetection!: () => void;
  const detectionGate = new Promise<void>((resolve) => {
    emitDetection = resolve;
  });
  const initializeRequests: Request[] = [];
  const runtimeRequests: Request[] = [];
  const previewRequests: Request[] = [];
  const unhandledPaths: string[] = [];

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
    if (path === '/api/v1/cameras/imx708/preview.mjpeg' && request.method() === 'GET') {
      previewRequests.push(request);
      await route.fulfill({
        contentType: 'image/jpeg',
        body: Buffer.from(JPEG_BASE64, 'base64'),
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

  return { initializeRequests, runtimeRequests, previewRequests, unhandledPaths, emitDetection };
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
  for (const value of ['RTSPS / TLS', 'SRTP', 'RTP/SAVP', 'sdes']) {
    await expect(page.getByText(value, { exact: true })).toBeVisible();
  }

  const image = page.getByRole('img', { name: 'imx708 camera preview' });
  await expect(image).toBeVisible();
  await expect.poll(() => image.evaluate((element: HTMLImageElement) => ({
    complete: element.complete,
    width: element.naturalWidth,
    height: element.naturalHeight,
  }))).toEqual({ complete: true, width: 320, height: 180 });
  expect(api.previewRequests).toHaveLength(1);
  expect(new URL(api.previewRequests[0].url()).pathname)
    .toBe('/api/v1/cameras/imx708/preview.mjpeg');
  expect(new URL(api.previewRequests[0].url()).search).toBe('?generation=1');
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
  await expect(image).toBeVisible();
  await page.getByRole('link', { name: 'Dashboard' }).click();
  await expect(page.getByRole('heading', { name: 'Operational dashboard' })).toBeVisible();
  await expect(image).toBeVisible();
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
  await expect(page.getByRole('img', { name: 'imx708 camera preview' })).toBeVisible();
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
