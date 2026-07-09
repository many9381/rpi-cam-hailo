const healthStatus = document.querySelector('#health-status');
const streamUrl = document.querySelector('#stream-url');
const aiStatus = document.querySelector('#ai-status');
const cameraList = document.querySelector('#camera-list');
const snapshotLabel = document.querySelector('#snapshot-label');
const snapshotImage = document.querySelector('#snapshot-image');
const detectionOverlay = document.querySelector('#detection-overlay');
const refreshButton = document.querySelector('#refresh-button');
const detectionCount = document.querySelector('#detection-count');
const detectionList = document.querySelector('#detection-list');
let detectionEventSource = null;
let latestDetectionSnapshot = {events: []};
let activeSnapshotCameraId = '';
let snapshotRequestSequence = 0;

function formatConfidence(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 'n/a';
  }
  return `${(value * 100).toFixed(1)}%`;
}

function formatBox(box) {
  if (!box) {
    return 'n/a';
  }
  const values = [box.x, box.y, box.width, box.height];
  if (values.some((value) => typeof value !== 'number' || !Number.isFinite(value))) {
    return 'n/a';
  }
  return `x ${box.x.toFixed(3)}, y ${box.y.toFixed(3)}, w ${box.width.toFixed(3)}, h ${box.height.toFixed(3)}`;
}

function toPercent(value) {
  return `${Number((value * 100).toFixed(3))}%`;
}

function normalizeOverlayBox(box) {
  if (!box) {
    return null;
  }
  const values = [box.x, box.y, box.width, box.height];
  if (values.some((value) => typeof value !== 'number' || !Number.isFinite(value))) {
    return null;
  }
  if (box.width <= 0 || box.height <= 0) {
    return null;
  }

  const x = Math.min(Math.max(box.x, 0), 1);
  const y = Math.min(Math.max(box.y, 0), 1);
  const right = Math.min(Math.max(box.x + box.width, 0), 1);
  const bottom = Math.min(Math.max(box.y + box.height, 0), 1);
  const width = right - x;
  const height = bottom - y;
  if (width <= 0 || height <= 0) {
    return null;
  }

  return {
    left: toPercent(x),
    top: toPercent(y),
    width: toPercent(width),
    height: toPercent(height),
  };
}

function buildDetectionRows(snapshot) {
  const rows = [];
  for (const event of snapshot?.events || []) {
    const detections = Array.isArray(event.detections) ? event.detections : [];
    if (detections.length === 0) {
      rows.push({
        cameraId: event.camera_id || '',
        modelId: event.model_id || '',
        modelKind: event.model_kind || '',
        resultState: event.result_state || '',
        frameSequence: event.frame_sequence ?? 0,
        label: '',
        confidence: undefined,
        box: undefined,
      });
      continue;
    }

    for (const detection of detections) {
      rows.push({
        cameraId: event.camera_id || '',
        modelId: event.model_id || '',
        modelKind: event.model_kind || '',
        resultState: event.result_state || '',
        frameSequence: event.frame_sequence ?? 0,
        label: detection.label || '',
        confidence: detection.confidence,
        box: detection.box,
      });
    }
  }
  return rows;
}

function buildOverlayDetections(snapshot, cameraId) {
  if (!cameraId) {
    return [];
  }

  const rows = [];
  for (const event of snapshot?.events || []) {
    if (event.camera_id !== cameraId) {
      continue;
    }
    const detections = Array.isArray(event.detections) ? event.detections : [];
    for (const detection of detections) {
      const box = normalizeOverlayBox(detection.box);
      if (!box) {
        continue;
      }
      rows.push({
        label: detection.label || 'n/a',
        confidence: detection.confidence,
        box,
        frameSequence: event.frame_sequence ?? 0,
        modelId: event.model_id || 'unknown',
      });
    }
  }
  return rows;
}

function renderDetections(snapshot, targets = {list: detectionList, count: detectionCount}) {
  const rows = buildDetectionRows(snapshot);
  const {list, count} = targets;

  if (count) {
    count.textContent = String(rows.length);
  }
  if (!list) {
    return;
  }

  list.innerHTML = '';
  if (rows.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'detection-empty';
    empty.textContent = 'No detections';
    list.appendChild(empty);
    return;
  }

  for (const row of rows) {
    const item = document.createElement('div');
    item.className = 'detection-row';

    const label = document.createElement('strong');
    label.textContent = row.label || 'n/a';

    const confidence = document.createElement('span');
    confidence.className = 'detection-confidence';
    confidence.textContent = formatConfidence(row.confidence);

    const model = document.createElement('span');
    model.textContent = `${row.modelId || 'unknown'} / ${row.modelKind || 'unknown'}`;

    const state = document.createElement('span');
    state.textContent = row.resultState || 'unknown';

    const frame = document.createElement('span');
    frame.textContent = `frame ${row.frameSequence}`;

    const box = document.createElement('span');
    box.className = 'detection-box';
    box.textContent = formatBox(row.box);

    item.append(label, confidence, model, state, frame, box);
    list.appendChild(item);
  }
}

function renderDetectionOverlay(snapshot, cameraId, target = detectionOverlay) {
  if (!target) {
    return;
  }

  target.innerHTML = '';
  for (const row of buildOverlayDetections(snapshot, cameraId)) {
    const box = document.createElement('div');
    box.className = 'overlay-box';
    box.style.left = row.box.left;
    box.style.top = row.box.top;
    box.style.width = row.box.width;
    box.style.height = row.box.height;

    const label = document.createElement('span');
    label.className = 'overlay-label';
    label.textContent = `${row.label} ${formatConfidence(row.confidence)}`;
    box.appendChild(label);
    target.appendChild(box);
  }
}

function clearDetectionOverlay(target = detectionOverlay) {
  renderDetectionOverlay({events: []}, '', target);
}

function renderDetectionSnapshot(
  snapshot,
  targets = {list: detectionList, count: detectionCount, overlay: detectionOverlay},
) {
  latestDetectionSnapshot = snapshot || {events: []};
  renderDetections(latestDetectionSnapshot, targets);
  renderDetectionOverlay(
    latestDetectionSnapshot,
    activeSnapshotCameraId,
    targets.overlay,
  );
}

function defaultEventSourceConstructor() {
  if (typeof EventSource === 'function') {
    return EventSource;
  }
  return null;
}

function startDetectionStream(
  url = '/api/v1/ai/detections/stream',
  targets = {list: detectionList, count: detectionCount},
  EventSourceCtor = defaultEventSourceConstructor(),
) {
  if (typeof EventSourceCtor !== 'function') {
    return null;
  }

  if (detectionEventSource && typeof detectionEventSource.close === 'function') {
    detectionEventSource.close();
  }

  const source = new EventSourceCtor(url);
  source.addEventListener('detections', (message) => {
    try {
      renderDetectionSnapshot(JSON.parse(message.data), targets);
    } catch (error) {
      if (typeof console !== 'undefined' && typeof console.warn === 'function') {
        console.warn('Ignoring malformed detection stream event', error);
      }
    }
  });
  source.onerror = () => {};

  detectionEventSource = source;
  return source;
}

async function readJson(path) {
  const response = await fetch(path);
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.message || body.code || `Request failed: ${path}`);
  }
  return body;
}

function renderCameras(cameras) {
  cameraList.innerHTML = '';
  if (cameras.length === 0) {
    const item = document.createElement('li');
    item.className = 'camera-item';
    item.textContent = 'No cameras registered';
    cameraList.appendChild(item);
    return;
  }

  for (const camera of cameras) {
    const item = document.createElement('li');
    item.className = 'camera-item';
    item.dataset.cameraId = camera.id;

    const title = document.createElement('strong');
    title.textContent = camera.id;

    const state = document.createElement('span');
    state.textContent = camera.state;

    item.append(title, state);
    item.addEventListener('click', () => loadSnapshot(camera.id));
    cameraList.appendChild(item);
  }
}

async function loadSnapshot(cameraId) {
  const requestSequence = snapshotRequestSequence + 1;
  snapshotRequestSequence = requestSequence;
  activeSnapshotCameraId = cameraId;
  snapshotLabel.textContent = `Loading ${cameraId}`;
  snapshotImage.removeAttribute('src');
  clearDetectionOverlay();

  try {
    const response = await fetch(`/api/v1/cameras/${encodeURIComponent(cameraId)}/snapshot.jpg`);
    if (requestSequence !== snapshotRequestSequence) {
      return;
    }
    if (!response.ok) {
      const body = await response.json();
      if (requestSequence !== snapshotRequestSequence) {
        return;
      }
      snapshotLabel.textContent = body.code || 'Unavailable';
      snapshotRequestSequence += 1;
      activeSnapshotCameraId = '';
      clearDetectionOverlay();
      return;
    }

    const blob = await response.blob();
    if (requestSequence !== snapshotRequestSequence) {
      return;
    }
    snapshotImage.src = URL.createObjectURL(blob);
    snapshotLabel.textContent = cameraId;
    renderDetectionOverlay(latestDetectionSnapshot, activeSnapshotCameraId);
  } catch (error) {
    if (requestSequence !== snapshotRequestSequence) {
      return;
    }
    snapshotLabel.textContent = error.message;
    snapshotRequestSequence += 1;
    activeSnapshotCameraId = '';
    clearDetectionOverlay();
  }
}

async function refresh() {
  try {
    const [health, stream, cameras, detections] = await Promise.all([
      readJson('/api/v1/health'),
      readJson('/api/v1/stream'),
      readJson('/api/v1/cameras'),
      readJson('/api/v1/ai/detections'),
    ]);

    healthStatus.textContent = health.status || 'unknown';
    streamUrl.textContent = stream.url || 'unavailable';
    aiStatus.textContent = cameras.ai?.enabled ? 'Enabled' : 'Disabled';
    renderCameras(cameras.cameras || []);
    renderDetectionSnapshot(detections);

    if ((cameras.cameras || []).length > 0) {
      loadSnapshot(cameras.cameras[0].id);
    } else {
      snapshotRequestSequence += 1;
      activeSnapshotCameraId = '';
      renderDetectionOverlay({events: []}, activeSnapshotCameraId);
      snapshotLabel.textContent = 'Unavailable';
    }
  } catch (error) {
    healthStatus.textContent = 'error';
    streamUrl.textContent = error.message;
    aiStatus.textContent = 'Unknown';
    renderCameras([]);
    snapshotRequestSequence += 1;
    activeSnapshotCameraId = '';
    renderDetectionSnapshot({events: []});
    snapshotLabel.textContent = 'Unavailable';
  }
}

refreshButton.addEventListener('click', refresh);
refresh();
startDetectionStream();

if (typeof module !== 'undefined') {
  module.exports = {
    buildOverlayDetections,
    buildDetectionRows,
    formatBox,
    formatConfidence,
    loadSnapshot,
    renderDetectionOverlay,
    renderDetections,
    renderDetectionSnapshot,
    startDetectionStream,
  };
}
