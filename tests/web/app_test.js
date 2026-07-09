const assert = require('node:assert/strict');
const test = require('node:test');

function makeElement() {
  const element = {
    className: '',
    children: [],
    dataset: {},
    style: {},
    _innerHTML: '',
    textContent: '',
    append(...children) {
      this.children.push(...children);
    },
    appendChild(child) {
      this.children.push(child);
    },
    addEventListener() {},
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

function loadApp() {
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
  global.fetch = async (path) => ({
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
  });
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
