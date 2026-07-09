const healthStatus = document.querySelector('#health-status');
const streamUrl = document.querySelector('#stream-url');
const streamSecurity = document.querySelector('#stream-security');
const aiStatus = document.querySelector('#ai-status');
const aiStatusDetail = document.querySelector('#ai-status-detail');
const cameraList = document.querySelector('#camera-list');
const snapshotLabel = document.querySelector('#snapshot-label');
const snapshotImage = document.querySelector('#snapshot-image');
const detectionOverlay = document.querySelector('#detection-overlay');
const refreshButton = document.querySelector('#refresh-button');
const aiRestartButton = document.querySelector('#ai-restart-button');
const aiControlStatus = document.querySelector('#ai-control-status');
const detectionCount = document.querySelector('#detection-count');
const detectionList = document.querySelector('#detection-list');
const runnerCount = document.querySelector('#runner-count');
const runnerList = document.querySelector('#runner-list');
const statusPollingIntervalMs = 5000;
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

function toCounter(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return 0;
  }
  return value;
}

function toText(value, fallback = '') {
  if (typeof value !== 'string' || value.length === 0) {
    return fallback;
  }
  return value;
}

function buildStreamSecurityView(stream) {
  if (typeof stream?.control_tls !== 'boolean' ||
      typeof stream?.media_srtp !== 'boolean') {
    return 'Stream security unavailable';
  }

  const control = stream.control_tls ? 'RTSPS control' : 'RTSP control';
  const media = stream.media_srtp ? 'SRTP media' : 'RTP media';
  const zeroizeCount = stream.secure_media?.per_media_key_zeroize_count;
  const zeroizeDetail =
      Number.isSafeInteger(zeroizeCount) && zeroizeCount >= 0
          ? ` / key zeroize ${zeroizeCount}`
          : '';
  return `${control} / ${media}${zeroizeDetail}`;
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

function buildAiStatusView(ai) {
  const hasStatus = ai !== null && typeof ai === 'object';
  const enabled = ai?.enabled === true;
  const state = toText(
    ai?.state,
    hasStatus ? (enabled ? 'unknown' : 'disabled') : 'unknown',
  );
  const backend = toText(
    ai?.backend,
    enabled ? 'unknown' : (state === 'unknown' ? 'unknown' : 'disabled'),
  );
  const modelCount = toCounter(ai?.model_count);
  const runnerCount = toCounter(ai?.runner_count);
  const reason = toText(ai?.reason);
  const summary = !enabled && state === 'unknown'
    ? 'Unknown'
    : (enabled ? `${backend} / ${state}` : 'Disabled');
  const counts = `models ${modelCount} / runners ${runnerCount}`;

  return {
    summary,
    detail: reason ? `${counts} - ${reason}` : counts,
  };
}

function renderAiStatus(
  ai,
  targets = {summary: aiStatus, detail: aiStatusDetail},
) {
  const view = buildAiStatusView(ai);
  if (targets.summary) {
    targets.summary.textContent = view.summary;
  }
  if (targets.detail) {
    targets.detail.textContent = view.detail;
  }
}

function buildRunnerRows(ai) {
  const rows = [];
  const runners = Array.isArray(ai?.runners) ? ai.runners : [];
  for (const runner of runners) {
    rows.push({
      cameraId: runner.camera_id || '',
      modelId: runner.model_id || '',
      modelKind: runner.model_kind || '',
      submittedFrames: toCounter(runner.submitted_frames),
      processedFrames: toCounter(runner.processed_frames),
      droppedFrames: toCounter(runner.dropped_frames),
      lastErrorCode: runner.last_error_code || '',
      lastErrorMessage: runner.last_error_message || '',
    });
  }
  return rows;
}

function renderAiRunners(ai, targets = {list: runnerList, count: runnerCount}) {
  const rows = buildRunnerRows(ai);
  const {list, count} = targets;

  if (count) {
    count.textContent = `${rows.length} ${rows.length === 1 ? 'runner' : 'runners'}`;
  }
  if (!list) {
    return;
  }

  list.innerHTML = '';
  if (rows.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'runner-empty';
    empty.textContent = 'No AI runners';
    list.appendChild(empty);
    return;
  }

  for (const row of rows) {
    const item = document.createElement('div');
    item.className = row.lastErrorCode ? 'runner-row runner-row-error' : 'runner-row';

    const model = document.createElement('strong');
    model.textContent = row.modelId || 'unknown';

    const kind = document.createElement('span');
    kind.textContent = row.modelKind || 'unknown';

    const camera = document.createElement('span');
    camera.textContent = row.cameraId || 'unknown';

    const counters = document.createElement('span');
    counters.textContent =
      `submitted ${row.submittedFrames} / processed ${row.processedFrames} / dropped ${row.droppedFrames}`;

    const error = document.createElement('span');
    error.className = 'runner-error';
    error.textContent = row.lastErrorCode
      ? `${row.lastErrorCode}: ${row.lastErrorMessage || 'unknown'}`
      : 'ok';

    item.append(model, kind, camera, counters, error);
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

async function readJson(path, options) {
  const response = await fetch(path, options);
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

function renderStatusPayload(health, stream, cameras) {
  healthStatus.textContent = health.status || 'unknown';
  streamUrl.textContent = stream.url || 'unavailable';
  streamSecurity.textContent = buildStreamSecurityView(stream);
  renderAiStatus(cameras.ai);
  renderAiRunners(cameras.ai);
  renderCameras(cameras.cameras || []);
}

function renderStatusError(error) {
  healthStatus.textContent = 'error';
  streamUrl.textContent = error.message;
  streamSecurity.textContent = 'Stream security unavailable';
  renderAiStatus({state: 'unknown', backend: 'unknown', reason: error.message});
  renderAiRunners({runners: []});
  renderCameras([]);
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

async function refreshStatusOnly() {
  try {
    const [health, stream, cameras] = await Promise.all([
      readJson('/api/v1/health'),
      readJson('/api/v1/stream'),
      readJson('/api/v1/cameras'),
    ]);

    renderStatusPayload(health, stream, cameras);
  } catch (error) {
    renderStatusError(error);
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

    renderStatusPayload(health, stream, cameras);
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
    renderStatusError(error);
    snapshotRequestSequence += 1;
    activeSnapshotCameraId = '';
    renderDetectionSnapshot({events: []});
    snapshotLabel.textContent = 'Unavailable';
  }
}

async function restartAi() {
  aiRestartButton.disabled = true;
  aiControlStatus.textContent = 'Restarting AI';

  try {
    const restarted = await readJson('/api/v1/ai/restart', {method: 'POST'});
    aiControlStatus.textContent = restarted.status || 'restarted';
    if (restarted.ai && typeof restarted.ai === 'object') {
      renderAiStatus(restarted.ai);
      renderAiRunners(restarted.ai);
    } else {
      await refreshStatusOnly();
    }
  } catch (error) {
    aiControlStatus.textContent = error.message;
  } finally {
    aiRestartButton.disabled = false;
  }
}

function startStatusPolling(
  intervalMs = statusPollingIntervalMs,
  scheduler = globalThis,
  refreshFn = refreshStatusOnly,
) {
  if (!scheduler || typeof scheduler.setInterval !== 'function') {
    return null;
  }
  const handle = scheduler.setInterval(() => refreshFn(), intervalMs);
  if (handle && typeof handle.unref === 'function') {
    handle.unref();
  }
  return handle;
}

refreshButton.addEventListener('click', refresh);
aiRestartButton.addEventListener('click', restartAi);
refresh();
startDetectionStream();
startStatusPolling();

if (typeof module !== 'undefined') {
  module.exports = {
    buildAiStatusView,
    buildOverlayDetections,
    buildDetectionRows,
    buildRunnerRows,
    buildStreamSecurityView,
    formatBox,
    formatConfidence,
    loadSnapshot,
    restartAi,
    refreshStatusOnly,
    renderAiStatus,
    renderAiRunners,
    renderDetectionOverlay,
    renderDetections,
    renderDetectionSnapshot,
    startDetectionStream,
    startStatusPolling,
  };
}
