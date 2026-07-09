const assert = require('node:assert/strict');
const test = require('node:test');

function makeElement() {
  const element = {
    className: '',
    children: [],
    dataset: {},
    disabled: false,
    listeners: {},
    style: {},
    _innerHTML: '',
    textContent: '',
    append(...children) {
      this.children.push(...children);
    },
    appendChild(child) {
      this.children.push(child);
    },
    addEventListener(name, handler) {
      this.listeners[name] = handler;
    },
    click() {
      if (this.listeners.click) {
        return this.listeners.click();
      }
      return undefined;
    },
    removeAttribute() {},
  };
  Object.defineProperty(element, 'innerHTML', {
    get() {
      return this._innerHTML;
    },
    set(value) {
      this._innerHTML = value;
      if (value === '') {
        this.children = [];
      }
    },
  });
  return element;
}

function makeFakeEventSourceClass() {
  return class FakeEventSource {
    static instances = [];

    constructor(url) {
      this.url = url;
      this.closed = false;
      this.listeners = {};
      FakeEventSource.instances.push(this);
    }

    addEventListener(name, handler) {
      this.listeners[name] = handler;
    }

    close() {
      this.closed = true;
    }

    emit(name, payload) {
      if (this.listeners[name]) {
        this.listeners[name]({data: JSON.stringify(payload)});
      }
    }
  };
}

async function settleStartupRefresh() {
  await new Promise((resolve) => setImmediate(resolve));
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return {promise, resolve};
}

function loadApp(fetchImpl) {
  delete require.cache[require.resolve('../../web/app.js')];
  delete global.EventSource;
  const elements = {};
  global.document = {
    querySelector(selector) {
      if (!elements[selector]) {
        elements[selector] = makeElement();
      }
      return elements[selector];
    },
    createElement() {
      return makeElement();
    },
  };
  global.URL = {
    createObjectURL() {
      return 'blob:mock';
    },
  };
  global.fetch = fetchImpl || (async (path) => ({
    ok: true,
    async json() {
      if (path === '/api/v1/health') {
        return {status: 'ok'};
      }
      if (path === '/api/v1/stream') {
        return {url: 'rtsp://camera.local/imx708/main'};
      }
      if (path === '/api/v1/cameras') {
        return {ai: {enabled: false}, cameras: []};
      }
      if (path === '/api/v1/ai/detections') {
        return {events: []};
      }
      return {};
    },
    async blob() {
      return new Blob();
    },
  }));
  return {...require('../../web/app.js'), elements};
}

test('buildDetectionRows returns empty rows for empty snapshot', () => {
  const {buildDetectionRows} = loadApp();

  assert.deepEqual(buildDetectionRows({events: []}), []);
});

test('buildDetectionRows flattens event detections', () => {
  const {buildDetectionRows} = loadApp();

  const rows = buildDetectionRows({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        model_kind: 'object_detection',
        result_state: 'decoded',
        frame_sequence: 42,
        detections: [
          {
            label: 'car',
            confidence: 0.876,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  });

  assert.deepEqual(rows, [
    {
      cameraId: 'imx708-main',
      modelId: 'objects',
      modelKind: 'object_detection',
      resultState: 'decoded',
      frameSequence: 42,
      label: 'car',
      confidence: 0.876,
      box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
    },
  ]);
});

test('buildDetectionRows preserves event state without detections', () => {
  const {buildDetectionRows} = loadApp();

  const rows = buildDetectionRows({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'pose',
        model_kind: 'pose',
        result_state: 'no_detections',
        frame_sequence: 43,
        detections: [],
      },
    ],
  });

  assert.deepEqual(rows, [
    {
      cameraId: 'imx708-main',
      modelId: 'pose',
      modelKind: 'pose',
      resultState: 'no_detections',
      frameSequence: 43,
      label: '',
      confidence: undefined,
      box: undefined,
    },
  ]);
});

test('formatConfidence renders percentages', () => {
  const {formatConfidence} = loadApp();

  assert.equal(formatConfidence(0.876), '87.6%');
  assert.equal(formatConfidence(undefined), 'n/a');
});

test('formatBox renders normalized coordinates', () => {
  const {formatBox} = loadApp();

  assert.equal(
    formatBox({x: 0.1234, y: 0.2, width: 0.3333, height: 0.4444}),
    'x 0.123, y 0.200, w 0.333, h 0.444',
  );
  assert.equal(formatBox(undefined), 'n/a');
});

test('buildStreamSecurityView renders stream transport security', () => {
  const {buildStreamSecurityView} = loadApp();

  assert.equal(
    buildStreamSecurityView({control_tls: true, media_srtp: true}),
    'RTSPS control / SRTP media',
  );
  assert.equal(
    buildStreamSecurityView({control_tls: true, media_srtp: false}),
    'RTSPS control / RTP media',
  );
  assert.equal(
    buildStreamSecurityView({control_tls: false, media_srtp: true}),
    'RTSP control / SRTP media',
  );
  assert.equal(
    buildStreamSecurityView({control_tls: false, media_srtp: false}),
    'RTSP control / RTP media',
  );
});

test('buildStreamSecurityView reports unavailable for partial stream status', () => {
  const {buildStreamSecurityView} = loadApp();

  assert.equal(buildStreamSecurityView({}), 'Stream security unavailable');
  assert.equal(
    buildStreamSecurityView({control_tls: true}),
    'Stream security unavailable',
  );
  assert.equal(
    buildStreamSecurityView({control_tls: 'true', media_srtp: true}),
    'Stream security unavailable',
  );
  assert.equal(
    buildStreamSecurityView({control_tls: true, media_srtp: 1}),
    'Stream security unavailable',
  );
  assert.equal(buildStreamSecurityView(undefined), 'Stream security unavailable');
});

test('renderDetections writes empty state', () => {
  const {renderDetections} = loadApp();
  const list = makeElement();
  const count = makeElement();

  renderDetections({events: []}, {list, count});

  assert.equal(count.textContent, '0');
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].textContent, 'No detections');
});

test('renderDetections writes compact rows', () => {
  const {renderDetections} = loadApp();
  const list = makeElement();
  const count = makeElement();

  renderDetections({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        model_kind: 'object_detection',
        result_state: 'decoded',
        frame_sequence: 42,
        detections: [
          {
            label: 'car',
            confidence: 0.876,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  }, {list, count});

  assert.equal(count.textContent, '1');
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].children[0].textContent, 'car');
  assert.equal(list.children[0].children[1].textContent, '87.6%');
  assert.equal(list.children[0].children[2].textContent, 'objects / object_detection');
  assert.equal(list.children[0].children[3].textContent, 'decoded');
  assert.equal(list.children[0].children[4].textContent, 'frame 42');
  assert.equal(
    list.children[0].children[5].textContent,
    'x 0.100, y 0.200, w 0.300, h 0.400',
  );
});

test('renderDetections writes model state rows without detections', () => {
  const {renderDetections} = loadApp();
  const list = makeElement();
  const count = makeElement();

  renderDetections({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'pose',
        model_kind: 'pose',
        result_state: 'no_detections',
        frame_sequence: 43,
        detections: [],
      },
    ],
  }, {list, count});

  assert.equal(count.textContent, '1');
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].children[0].textContent, 'n/a');
  assert.equal(list.children[0].children[1].textContent, 'n/a');
  assert.equal(list.children[0].children[2].textContent, 'pose / pose');
  assert.equal(list.children[0].children[3].textContent, 'no_detections');
  assert.equal(list.children[0].children[4].textContent, 'frame 43');
  assert.equal(list.children[0].children[5].textContent, 'n/a');
});

test('renderDetections clears stale rows before rendering empty state', () => {
  const {renderDetections} = loadApp();
  const list = makeElement();
  const count = makeElement();

  renderDetections({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        model_kind: 'object_detection',
        result_state: 'decoded',
        frame_sequence: 42,
        detections: [
          {
            label: 'car',
            confidence: 0.876,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  }, {list, count});
  renderDetections({events: []}, {list, count});

  assert.equal(count.textContent, '0');
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].textContent, 'No detections');
});

test('buildAiStatusView normalizes runtime state details', () => {
  const {buildAiStatusView} = loadApp();

  assert.deepEqual(buildAiStatusView({
    enabled: true,
    backend: 'hailo',
    state: 'ready',
    model_count: 2,
    runner_count: 1,
    reason: 'AI runtime ready',
  }), {
    summary: 'hailo / ready',
    detail: 'models 2 / runners 1 - AI runtime ready',
  });
});

test('buildAiStatusView preserves disabled and unknown states', () => {
  const {buildAiStatusView} = loadApp();

  assert.deepEqual(buildAiStatusView({
    enabled: false,
    reason: 'disabled by config',
  }), {
    summary: 'Disabled',
    detail: 'models 0 / runners 0 - disabled by config',
  });

  assert.deepEqual(buildAiStatusView(undefined), {
    summary: 'Unknown',
    detail: 'models 0 / runners 0',
  });
});

test('renderAiStatus writes compact status details', () => {
  const {renderAiStatus} = loadApp();
  const summary = makeElement();
  const detail = makeElement();

  renderAiStatus({
    enabled: true,
    backend: 'hailo',
    state: 'backend_unavailable',
    model_count: 1,
    runner_count: 0,
    reason: 'Hailo device unavailable',
  }, {summary, detail});

  assert.equal(summary.textContent, 'hailo / backend_unavailable');
  assert.equal(
    detail.textContent,
    'models 1 / runners 0 - Hailo device unavailable',
  );
});

test('buildRunnerRows normalizes ai runner status', () => {
  const {buildRunnerRows} = loadApp();

  const rows = buildRunnerRows({
    runners: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        model_kind: 'object_detection',
        submitted_frames: 11,
        processed_frames: 10,
        dropped_frames: 1,
        last_error_code: 'E_AI_POSTPROCESS',
        last_error_message: 'malformed output',
      },
      {
        camera_id: 'imx708-main',
        model_id: 'pose',
        model_kind: 'pose',
        submitted_frames: 7,
        processed_frames: 7,
      },
    ],
  });

  assert.deepEqual(rows, [
    {
      cameraId: 'imx708-main',
      modelId: 'objects',
      modelKind: 'object_detection',
      submittedFrames: 11,
      processedFrames: 10,
      droppedFrames: 1,
      lastErrorCode: 'E_AI_POSTPROCESS',
      lastErrorMessage: 'malformed output',
    },
    {
      cameraId: 'imx708-main',
      modelId: 'pose',
      modelKind: 'pose',
      submittedFrames: 7,
      processedFrames: 7,
      droppedFrames: 0,
      lastErrorCode: '',
      lastErrorMessage: '',
    },
  ]);
});

test('renderAiRunners writes empty state', () => {
  const {renderAiRunners} = loadApp();
  const list = makeElement();
  const count = makeElement();

  renderAiRunners({runners: []}, {list, count});

  assert.equal(count.textContent, '0 runners');
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].textContent, 'No AI runners');
});

test('renderAiRunners writes compact runner rows', () => {
  const {renderAiRunners} = loadApp();
  const list = makeElement();
  const count = makeElement();

  renderAiRunners({
    runners: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        model_kind: 'object_detection',
        submitted_frames: 11,
        processed_frames: 10,
        dropped_frames: 1,
        last_error_code: 'E_AI_POSTPROCESS',
        last_error_message: 'malformed output',
      },
    ],
  }, {list, count});

  assert.equal(count.textContent, '1 runner');
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].children[0].textContent, 'objects');
  assert.equal(list.children[0].children[1].textContent, 'object_detection');
  assert.equal(list.children[0].children[2].textContent, 'imx708-main');
  assert.equal(
    list.children[0].children[3].textContent,
    'submitted 11 / processed 10 / dropped 1',
  );
  assert.equal(
    list.children[0].children[4].textContent,
    'E_AI_POSTPROCESS: malformed output',
  );
});

test('startup refresh renders ai runner status from cameras response', async () => {
  const app = loadApp(async (path) => ({
    ok: true,
    async json() {
      if (path === '/api/v1/health') {
        return {status: 'ok'};
      }
      if (path === '/api/v1/stream') {
        return {url: 'rtsp://camera.local/imx708/main'};
      }
      if (path === '/api/v1/cameras') {
        return {
          ai: {
            enabled: true,
            runners: [
              {
                camera_id: 'imx708-main',
                model_id: 'objects',
                model_kind: 'object_detection',
                submitted_frames: 4,
                processed_frames: 3,
                dropped_frames: 1,
                last_error_code: 'E_AI_POSTPROCESS',
                last_error_message: 'malformed output',
              },
            ],
          },
          cameras: [],
        };
      }
      if (path === '/api/v1/ai/detections') {
        return {events: []};
      }
      return {};
    },
    async blob() {
      return new Blob();
    },
  }));

  await settleStartupRefresh();

  assert.equal(app.elements['#runner-count'].textContent, '1 runner');
  assert.equal(app.elements['#runner-list'].children.length, 1);
  assert.equal(app.elements['#runner-list'].children[0].children[0].textContent, 'objects');
  assert.equal(
    app.elements['#runner-list'].children[0].children[3].textContent,
    'submitted 4 / processed 3 / dropped 1',
  );
  assert.equal(
    app.elements['#runner-list'].children[0].children[4].textContent,
    'E_AI_POSTPROCESS: malformed output',
  );
});

test('startup refresh renders stream security detail from stream response', async () => {
  const app = loadApp(async (path) => ({
    ok: true,
    async json() {
      if (path === '/api/v1/health') {
        return {status: 'ok'};
      }
      if (path === '/api/v1/stream') {
        return {
          control_tls: true,
          media_srtp: true,
          url: 'rtsps://camera.local/imx708/main',
        };
      }
      if (path === '/api/v1/cameras') {
        return {ai: {enabled: false}, cameras: []};
      }
      if (path === '/api/v1/ai/detections') {
        return {events: []};
      }
      return {};
    },
    async blob() {
      return new Blob();
    },
  }));

  await settleStartupRefresh();

  assert.equal(
    app.elements['#stream-security'].textContent,
    'RTSPS control / SRTP media',
  );
});

test('startup refresh renders ai runtime status details from cameras response', async () => {
  const app = loadApp(async (path) => ({
    ok: true,
    async json() {
      if (path === '/api/v1/health') {
        return {status: 'ok'};
      }
      if (path === '/api/v1/stream') {
        return {url: 'rtsp://camera.local/imx708/main'};
      }
      if (path === '/api/v1/cameras') {
        return {
          ai: {
            enabled: true,
            backend: 'hailo',
            state: 'backend_unavailable',
            model_count: 1,
            runner_count: 0,
            reason: 'Hailo device unavailable',
            runners: [],
          },
          cameras: [],
        };
      }
      if (path === '/api/v1/ai/detections') {
        return {events: []};
      }
      return {};
    },
    async blob() {
      return new Blob();
    },
  }));

  await settleStartupRefresh();

  assert.equal(app.elements['#ai-status'].textContent, 'hailo / backend_unavailable');
  assert.equal(
    app.elements['#ai-status-detail'].textContent,
    'models 1 / runners 0 - Hailo device unavailable',
  );
});

test('startup refresh renders unknown ai status on request failure', async () => {
  const app = loadApp(async (path) => ({
    ok: path !== '/api/v1/cameras',
    async json() {
      if (path === '/api/v1/health') {
        return {status: 'ok'};
      }
      if (path === '/api/v1/stream') {
        return {url: 'rtsp://camera.local/imx708/main'};
      }
      if (path === '/api/v1/cameras') {
        return {message: 'camera status unavailable'};
      }
      if (path === '/api/v1/ai/detections') {
        return {events: []};
      }
      return {};
    },
    async blob() {
      return new Blob();
    },
  }));

  await settleStartupRefresh();

  assert.equal(app.elements['#ai-status'].textContent, 'Unknown');
  assert.equal(
    app.elements['#ai-status-detail'].textContent,
    'models 0 / runners 0 - camera status unavailable',
  );
});

test('status-only refresh updates ai status without snapshot or detection requests', async () => {
  const app = loadApp();
  await settleStartupRefresh();
  const calls = [];

  global.fetch = async (path) => {
    calls.push(path);
    return {
      ok: true,
      async json() {
        if (path === '/api/v1/health') {
          return {status: 'ok'};
        }
        if (path === '/api/v1/stream') {
          return {url: 'rtsp://camera.local/imx708/main'};
        }
        if (path === '/api/v1/cameras') {
          return {
            ai: {
              enabled: true,
              backend: 'hailo',
              state: 'ready',
              model_count: 1,
              runner_count: 1,
              reason: 'AI runtime ready',
              runners: [
                {
                  camera_id: 'imx708-main',
                  model_id: 'objects',
                  model_kind: 'object_detection',
                  submitted_frames: 12,
                  processed_frames: 11,
                  dropped_frames: 1,
                },
              ],
            },
            cameras: [
              {id: 'imx708-main', state: 'running', snapshot_available: true},
            ],
          };
        }
        return {};
      },
      async blob() {
        throw new Error('snapshot should not be requested');
      },
    };
  };

  await app.refreshStatusOnly();

  assert.deepEqual(calls, [
    '/api/v1/health',
    '/api/v1/stream',
    '/api/v1/cameras',
  ]);
  assert.equal(app.elements['#ai-status'].textContent, 'hailo / ready');
  assert.equal(
    app.elements['#ai-status-detail'].textContent,
    'models 1 / runners 1 - AI runtime ready',
  );
  assert.equal(app.elements['#runner-count'].textContent, '1 runner');
  assert.equal(
    app.elements['#runner-list'].children[0].children[3].textContent,
    'submitted 12 / processed 11 / dropped 1',
  );
  assert.equal(app.elements['#camera-list'].children[0].dataset.cameraId, 'imx708-main');
});

test('status-only refresh failure preserves active snapshot and overlay', async () => {
  const app = loadApp();
  const overlay = app.elements['#detection-overlay'];
  await settleStartupRefresh();

  global.fetch = async () => ({
    ok: true,
    async blob() {
      return new Blob(['jpeg']);
    },
  });
  global.URL = {
    createObjectURL() {
      return 'blob:snapshot';
    },
  };

  await app.loadSnapshot('imx708-main');
  app.renderDetectionSnapshot({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 34,
        detections: [
          {
            label: 'person',
            confidence: 0.9,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  });
  assert.equal(overlay.children.length, 1);

  global.fetch = async (path) => ({
    ok: path !== '/api/v1/cameras',
    async json() {
      if (path === '/api/v1/cameras') {
        return {message: 'camera status unavailable'};
      }
      return {};
    },
  });

  await app.refreshStatusOnly();

  assert.equal(app.elements['#snapshot-label'].textContent, 'imx708-main');
  assert.equal(overlay.children.length, 1);
  assert.equal(app.elements['#ai-status'].textContent, 'Unknown');
  assert.equal(
    app.elements['#ai-status-detail'].textContent,
    'models 0 / runners 0 - camera status unavailable',
  );
});

test('restartAi renders response ai status without polling endpoints', async () => {
  const app = loadApp();
  const overlay = app.elements['#detection-overlay'];
  await settleStartupRefresh();
  const calls = [];

  global.fetch = async () => ({
    ok: true,
    async blob() {
      return new Blob(['jpeg']);
    },
  });
  global.URL = {
    createObjectURL() {
      return 'blob:snapshot';
    },
  };

  await app.loadSnapshot('imx708-main');
  app.renderDetectionSnapshot({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 36,
        detections: [
          {
            label: 'person',
            confidence: 0.9,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  });
  assert.equal(overlay.children.length, 1);

  global.fetch = async (path, options = {}) => {
    calls.push({path, method: options.method || 'GET'});
    return {
      ok: path !== '/api/v1/ai/detections',
      async json() {
        if (path === '/api/v1/ai/restart') {
          return {
            ai: {
              enabled: true,
              backend: 'hailo',
              state: 'ready',
              model_count: 1,
              runner_count: 1,
              reason: 'AI runtime ready',
              runners: [
                {
                  camera_id: 'imx708-main',
                  model_id: 'objects',
                  model_kind: 'object_detection',
                  submitted_frames: 18,
                  processed_frames: 17,
                  dropped_frames: 1,
                },
              ],
            },
            status: 'restarted',
          };
        }
        throw new Error(`unexpected request: ${path}`);
      },
      async blob() {
        throw new Error('snapshot should not be requested');
      },
    };
  };

  await app.restartAi();

  assert.deepEqual(calls, [
    {path: '/api/v1/ai/restart', method: 'POST'},
  ]);
  assert.equal(app.elements['#ai-control-status'].textContent, 'restarted');
  assert.equal(app.elements['#ai-restart-button'].disabled, false);
  assert.equal(app.elements['#ai-status'].textContent, 'hailo / ready');
  assert.equal(app.elements['#runner-count'].textContent, '1 runner');
  assert.equal(
    app.elements['#runner-list'].children[0].children[3].textContent,
    'submitted 18 / processed 17 / dropped 1',
  );
  assert.equal(app.elements['#snapshot-label'].textContent, 'imx708-main');
  assert.equal(overlay.children.length, 1);
});

test('restartAi falls back to status refresh when response omits ai', async () => {
  const app = loadApp();
  await settleStartupRefresh();
  const calls = [];

  global.fetch = async (path, options = {}) => {
    calls.push({path, method: options.method || 'GET'});
    return {
      ok: true,
      async json() {
        if (path === '/api/v1/ai/restart') {
          return {status: 'restarted'};
        }
        if (path === '/api/v1/health') {
          return {status: 'ok'};
        }
        if (path === '/api/v1/stream') {
          return {url: 'rtsp://camera.local/imx708/main'};
        }
        if (path === '/api/v1/cameras') {
          return {
            ai: {
              enabled: true,
              backend: 'hailo',
              state: 'ready',
              model_count: 1,
              runner_count: 0,
              reason: 'AI runtime ready',
              runners: [],
            },
            cameras: [],
          };
        }
        return {};
      },
    };
  };

  await app.restartAi();

  assert.deepEqual(calls, [
    {path: '/api/v1/ai/restart', method: 'POST'},
    {path: '/api/v1/health', method: 'GET'},
    {path: '/api/v1/stream', method: 'GET'},
    {path: '/api/v1/cameras', method: 'GET'},
  ]);
  assert.equal(app.elements['#ai-status'].textContent, 'hailo / ready');
});

test('restartAi shows pending state while request is in flight', async () => {
  const app = loadApp();
  await settleStartupRefresh();
  const restartResponse = deferred();

  global.fetch = async (path, options = {}) => {
    if (path === '/api/v1/ai/restart') {
      assert.equal(options.method, 'POST');
      return restartResponse.promise;
    }
    return {
      ok: true,
      async json() {
        if (path === '/api/v1/health') {
          return {status: 'ok'};
        }
        if (path === '/api/v1/stream') {
          return {url: 'rtsp://camera.local/imx708/main'};
        }
        if (path === '/api/v1/cameras') {
          return {ai: {enabled: false}, cameras: []};
        }
        return {};
      },
    };
  };

  const restart = app.restartAi();
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(app.elements['#ai-restart-button'].disabled, true);
  assert.equal(app.elements['#ai-control-status'].textContent, 'Restarting AI');

  restartResponse.resolve({
    ok: true,
    async json() {
      return {status: 'restarted'};
    },
  });
  await restart;

  assert.equal(app.elements['#ai-restart-button'].disabled, false);
  assert.equal(app.elements['#ai-control-status'].textContent, 'restarted');
});

test('restartAi failure preserves active snapshot and overlay', async () => {
  const app = loadApp();
  const overlay = app.elements['#detection-overlay'];
  await settleStartupRefresh();

  global.fetch = async () => ({
    ok: true,
    async blob() {
      return new Blob(['jpeg']);
    },
  });
  global.URL = {
    createObjectURL() {
      return 'blob:snapshot';
    },
  };

  await app.loadSnapshot('imx708-main');
  app.renderDetectionSnapshot({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 35,
        detections: [
          {
            label: 'person',
            confidence: 0.9,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  });
  assert.equal(overlay.children.length, 1);

  global.fetch = async (path, options = {}) => {
    assert.equal(path, '/api/v1/ai/restart');
    assert.equal(options.method, 'POST');
    return {
      ok: false,
      async json() {
        return {code: 'E_AI_RESTART', message: 'AI restart failed'};
      },
    };
  };

  await app.restartAi();

  assert.equal(app.elements['#ai-control-status'].textContent, 'AI restart failed');
  assert.equal(app.elements['#snapshot-label'].textContent, 'imx708-main');
  assert.equal(overlay.children.length, 1);
  assert.equal(app.elements['#ai-restart-button'].disabled, false);
});

test('restart button click invokes ai restart request', async () => {
  const app = loadApp();
  await settleStartupRefresh();
  const calls = [];

  global.fetch = async (path, options = {}) => {
    calls.push({path, method: options.method || 'GET'});
    return {
      ok: true,
      async json() {
        if (path === '/api/v1/ai/restart') {
          return {status: 'restarted'};
        }
        if (path === '/api/v1/health') {
          return {status: 'ok'};
        }
        if (path === '/api/v1/stream') {
          return {url: 'rtsp://camera.local/imx708/main'};
        }
        if (path === '/api/v1/cameras') {
          return {ai: {enabled: false}, cameras: []};
        }
        return {};
      },
    };
  };

  const clicked = app.elements['#ai-restart-button'].click();
  if (clicked && typeof clicked.then === 'function') {
    await clicked;
  } else {
    await new Promise((resolve) => setImmediate(resolve));
  }

  assert.equal(calls[0].path, '/api/v1/ai/restart');
  assert.equal(calls[0].method, 'POST');
});

test('startStatusPolling schedules status refresh and unrefs node timers', async () => {
  const {startStatusPolling} = loadApp();
  let scheduledCallback;
  let scheduledInterval = 0;
  let unrefCalled = false;
  let refreshes = 0;
  const scheduler = {
    setInterval(callback, intervalMs) {
      scheduledCallback = callback;
      scheduledInterval = intervalMs;
      return {
        unref() {
          unrefCalled = true;
        },
      };
    },
  };

  const handle = startStatusPolling(1234, scheduler, async () => {
    refreshes += 1;
  });

  assert.equal(scheduledInterval, 1234);
  assert.equal(unrefCalled, true);
  assert.equal(typeof handle.unref, 'function');
  await scheduledCallback();
  assert.equal(refreshes, 1);
});

test('startStatusPolling default callback refreshes status only', async () => {
  const app = loadApp();
  await settleStartupRefresh();
  let scheduledCallback;
  const scheduler = {
    setInterval(callback) {
      scheduledCallback = callback;
      return {};
    },
  };
  const calls = [];

  global.fetch = async (path) => {
    calls.push(path);
    return {
      ok: true,
      async json() {
        if (path === '/api/v1/health') {
          return {status: 'ok'};
        }
        if (path === '/api/v1/stream') {
          return {url: 'rtsp://camera.local/imx708/main'};
        }
        if (path === '/api/v1/cameras') {
          return {
            ai: {
              enabled: true,
              backend: 'hailo',
              state: 'ready',
              model_count: 1,
              runner_count: 0,
              reason: 'AI runtime ready',
              runners: [],
            },
            cameras: [],
          };
        }
        return {};
      },
    };
  };

  app.startStatusPolling(1000, scheduler);
  await scheduledCallback();

  assert.deepEqual(calls, [
    '/api/v1/health',
    '/api/v1/stream',
    '/api/v1/cameras',
  ]);
  assert.equal(app.elements['#ai-status'].textContent, 'hailo / ready');
});

test('buildOverlayDetections returns valid detections for active camera', () => {
  const {buildOverlayDetections} = loadApp();

  const rows = buildOverlayDetections({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 11,
        detections: [
          {
            label: 'person',
            confidence: 0.91,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
      {
        camera_id: 'other',
        model_id: 'objects',
        frame_sequence: 12,
        detections: [
          {
            label: 'cat',
            confidence: 0.80,
            box: {x: 0.5, y: 0.5, width: 0.1, height: 0.1},
          },
        ],
      },
    ],
  }, 'imx708-main');

  assert.equal(rows.length, 1);
  assert.equal(rows[0].label, 'person');
  assert.equal(rows[0].box.left, '10%');
  assert.equal(rows[0].box.top, '20%');
  assert.equal(rows[0].box.width, '30%');
  assert.equal(rows[0].box.height, '40%');
});

test('buildOverlayDetections ignores invalid boxes', () => {
  const {buildOverlayDetections} = loadApp();

  const rows = buildOverlayDetections({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 13,
        detections: [
          {label: 'bad', confidence: 1, box: {x: 0, y: 0, width: 0, height: 1}},
          {label: 'nan', confidence: 1, box: {x: Number.NaN, y: 0, width: 1, height: 1}},
        ],
      },
    ],
  }, 'imx708-main');

  assert.equal(rows.length, 0);
});

test('renderDetectionOverlay draws positioned boxes', () => {
  const {renderDetectionOverlay} = loadApp();
  const overlay = makeElement();

  renderDetectionOverlay({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 21,
        detections: [
          {
            label: 'person',
            confidence: 0.912,
            box: {x: 0.2, y: 0.3, width: 0.4, height: 0.5},
          },
        ],
      },
    ],
  }, 'imx708-main', overlay);

  assert.equal(overlay.children.length, 1);
  assert.equal(overlay.children[0].style.left, '20%');
  assert.equal(overlay.children[0].style.top, '30%');
  assert.equal(overlay.children[0].style.width, '40%');
  assert.equal(overlay.children[0].style.height, '50%');
  assert.equal(overlay.children[0].children[0].textContent, 'person 91.2%');
});

test('startDetectionStream renders incoming detections events', () => {
  const {startDetectionStream} = loadApp();
  const FakeEventSource = makeFakeEventSourceClass();
  const list = makeElement();
  const count = makeElement();

  const source = startDetectionStream(
    '/api/v1/ai/detections/stream',
    {list, count},
    FakeEventSource,
  );

  assert.equal(source.url, '/api/v1/ai/detections/stream');
  source.emit('detections', {
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        model_kind: 'object_detection',
        result_state: 'decoded',
        frame_sequence: 91,
        detections: [
          {
            label: 'person',
            confidence: 0.912,
            box: {x: 0.2, y: 0.3, width: 0.4, height: 0.5},
          },
        ],
      },
    ],
  });

  assert.equal(count.textContent, '1');
  assert.equal(list.children.length, 1);
  assert.equal(list.children[0].children[0].textContent, 'person');
  assert.equal(list.children[0].children[1].textContent, '91.2%');
  assert.equal(list.children[0].children[4].textContent, 'frame 91');
});

test('startDetectionStream returns null without EventSource support', () => {
  const {startDetectionStream} = loadApp();

  const source = startDetectionStream(
    '/api/v1/ai/detections/stream',
    {list: makeElement(), count: makeElement()},
    undefined,
  );

  assert.equal(source, null);
});

test('startDetectionStream keeps EventSource open for browser reconnect', () => {
  const {startDetectionStream} = loadApp();
  const FakeEventSource = makeFakeEventSourceClass();

  const source = startDetectionStream(
    '/api/v1/ai/detections/stream',
    {list: makeElement(), count: makeElement()},
    FakeEventSource,
  );

  source.onerror(new Error('network'));

  assert.equal(source.closed, false);
});

test('startDetectionStream updates overlay for active snapshot camera', async () => {
  const {loadSnapshot, startDetectionStream} = loadApp();
  const FakeEventSource = makeFakeEventSourceClass();
  const list = makeElement();
  const count = makeElement();
  const overlay = makeElement();

  global.fetch = async () => ({
    ok: true,
    async blob() {
      return new Blob(['jpeg']);
    },
  });
  global.URL = {
    createObjectURL() {
      return 'blob:snapshot';
    },
  };

  await loadSnapshot('imx708-main');
  const source = startDetectionStream(
    '/api/v1/ai/detections/stream',
    {list, count, overlay},
    FakeEventSource,
  );
  source.emit('detections', {
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 31,
        detections: [
          {
            label: 'person',
            confidence: 0.9,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  });

  assert.equal(count.textContent, '1');
  assert.equal(overlay.children.length, 1);
  assert.equal(overlay.children[0].style.left, '10%');
});

test('startDetectionStream default targets update page overlay', async () => {
  const app = loadApp();
  const FakeEventSource = makeFakeEventSourceClass();
  await settleStartupRefresh();
  global.EventSource = FakeEventSource;
  global.fetch = async () => ({
    ok: true,
    async blob() {
      return new Blob(['jpeg']);
    },
  });
  global.URL = {
    createObjectURL() {
      return 'blob:snapshot';
    },
  };

  await app.loadSnapshot('imx708-main');
  const source = app.startDetectionStream();
  source.emit('detections', {
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 32,
        detections: [
          {
            label: 'person',
            confidence: 0.9,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  });

  assert.equal(app.elements['#detection-count'].textContent, '1');
  assert.equal(app.elements['#detection-overlay'].children.length, 1);
  assert.equal(app.elements['#detection-overlay'].children[0].style.left, '10%');
});

test('loadSnapshot clears overlay when snapshot fetch fails', async () => {
  const app = loadApp();
  const overlay = app.elements['#detection-overlay'];
  await settleStartupRefresh();

  global.fetch = async () => ({
    ok: true,
    async blob() {
      return new Blob(['jpeg']);
    },
  });
  global.URL = {
    createObjectURL() {
      return 'blob:snapshot';
    },
  };

  await app.loadSnapshot('imx708-main');
  app.renderDetectionSnapshot({
    events: [
      {
        camera_id: 'imx708-main',
        model_id: 'objects',
        frame_sequence: 33,
        detections: [
          {
            label: 'person',
            confidence: 0.9,
            box: {x: 0.1, y: 0.2, width: 0.3, height: 0.4},
          },
        ],
      },
    ],
  });
  assert.equal(overlay.children.length, 1);

  global.fetch = async () => ({
    ok: false,
    async json() {
      return {code: 'E_SNAPSHOT'};
    },
  });

  await app.loadSnapshot('imx708-main');

  assert.equal(app.elements['#snapshot-label'].textContent, 'E_SNAPSHOT');
  assert.equal(overlay.children.length, 0);
});

test('loadSnapshot ignores stale snapshot responses', async () => {
  const app = loadApp();
  await settleStartupRefresh();
  const requests = {};

  global.fetch = (path) => {
    const cameraId = decodeURIComponent(path.match(/cameras\/([^/]+)\/snapshot/)[1]);
    requests[cameraId] = deferred();
    return requests[cameraId].promise;
  };
  global.URL = {
    createObjectURL(blob) {
      return `blob:${blob.cameraId}`;
    },
  };

  const first = app.loadSnapshot('first-camera');
  const second = app.loadSnapshot('second-camera');

  requests['second-camera'].resolve({
    ok: true,
    async blob() {
      return {cameraId: 'second-camera'};
    },
  });
  await second;

  assert.equal(app.elements['#snapshot-label'].textContent, 'second-camera');
  assert.equal(app.elements['#snapshot-image'].src, 'blob:second-camera');

  requests['first-camera'].resolve({
    ok: true,
    async blob() {
      return {cameraId: 'first-camera'};
    },
  });
  await first;

  assert.equal(app.elements['#snapshot-label'].textContent, 'second-camera');
  assert.equal(app.elements['#snapshot-image'].src, 'blob:second-camera');
});
