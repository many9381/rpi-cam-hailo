const healthStatus = document.querySelector('#health-status');
const streamUrl = document.querySelector('#stream-url');
const aiStatus = document.querySelector('#ai-status');
const cameraList = document.querySelector('#camera-list');
const snapshotLabel = document.querySelector('#snapshot-label');
const snapshotImage = document.querySelector('#snapshot-image');
const refreshButton = document.querySelector('#refresh-button');

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
  snapshotLabel.textContent = `Loading ${cameraId}`;
  snapshotImage.removeAttribute('src');

  try {
    const response = await fetch(`/api/v1/cameras/${encodeURIComponent(cameraId)}/snapshot.jpg`);
    if (!response.ok) {
      const body = await response.json();
      snapshotLabel.textContent = body.code || 'Unavailable';
      return;
    }

    const blob = await response.blob();
    snapshotImage.src = URL.createObjectURL(blob);
    snapshotLabel.textContent = cameraId;
  } catch (error) {
    snapshotLabel.textContent = error.message;
  }
}

async function refresh() {
  try {
    const [health, stream, cameras] = await Promise.all([
      readJson('/api/v1/health'),
      readJson('/api/v1/stream'),
      readJson('/api/v1/cameras'),
    ]);

    healthStatus.textContent = health.status || 'unknown';
    streamUrl.textContent = stream.url || 'unavailable';
    aiStatus.textContent = cameras.ai?.enabled ? 'Enabled' : 'Disabled';
    renderCameras(cameras.cameras || []);

    if ((cameras.cameras || []).length > 0) {
      loadSnapshot(cameras.cameras[0].id);
    } else {
      snapshotLabel.textContent = 'Unavailable';
    }
  } catch (error) {
    healthStatus.textContent = 'error';
    streamUrl.textContent = error.message;
    aiStatus.textContent = 'Unknown';
    renderCameras([]);
    snapshotLabel.textContent = 'Unavailable';
  }
}

refreshButton.addEventListener('click', refresh);
refresh();
