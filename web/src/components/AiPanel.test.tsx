import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AiStatus } from '../api/types';
import { AiPanel } from './AiPanel';

const base: AiStatus = {
  enabled: true, backend: 'hailo', state: 'ready', model_count: 2,
  runner_count: 2, reason: 'AI runtime ready',
  models: [
    { id: 'objects', kind: 'object_detection', input_width: 640,
      input_height: 640, input_format: 'rgb8', letterbox: true,
      output_name: 'objects-out', confidence_threshold: 0.4, labels: 'coco80' },
    { id: 'pose', kind: 'pose', input_width: 256, input_height: 256,
      input_format: 'rgb8', letterbox: false, output_name: 'pose-out',
      confidence_threshold: 0.3, labels: 'pose17' },
  ],
  runners: [
    { camera_id: 'cam-a', model_id: 'objects', model_kind: 'object_detection',
      submitted_frames: 11, processed_frames: 10, dropped_frames: 1,
      last_preprocess_ms: 1.2, last_inference_ms: 3.4,
      last_processed_sequence: 11,
      last_error_code: 'E_AI_POSTPROCESS', last_error_message: 'malformed output' },
    { camera_id: 'cam-a', model_id: 'pose', model_kind: 'pose',
      submitted_frames: 7, processed_frames: 7, dropped_frames: 0,
      last_preprocess_ms: 0.9, last_inference_ms: 2.8,
      last_processed_sequence: 7,
      last_error_code: '', last_error_message: '' },
  ],
};

const detections = { events: [
  { camera_id: 'cam-a', model_id: 'objects', model_kind: 'object_detection',
    result_state: 'decoded', frame_sequence: 5, frame_timestamp_ns: 50,
    detections: [{ class_id: 2, label: 'car', confidence: 0.88,
      box: { x: 0.1, y: 0.1, width: 0.2, height: 0.2 }, keypoints: [] }] },
  { camera_id: 'cam-a', model_id: 'pose', model_kind: 'pose',
    result_state: 'decoded', frame_sequence: 5, frame_timestamp_ns: 50,
    detections: [{ class_id: 0, label: 'person', confidence: 0.91,
      box: { x: 0.2, y: 0.2, width: 0.3, height: 0.5 },
      keypoints: [{ name: 'nose', x: 0.3, y: 0.25, confidence: 0.9 }] }] },
] };

const renderPanel = (
  onRestart: () => Promise<void> = vi.fn(async () => undefined),
) => render(
  <AiPanel ai={base} detections={detections} streamStatus="live"
    onRestart={onRestart} />,
);

afterEach(cleanup);

describe('AiPanel', () => {
  it('renders multiple model kinds, runner counters, and runner errors', () => {
    const { container } = renderPanel();

    const aiColumns = within(container.querySelector('.ai-columns')! as HTMLElement);
    expect(aiColumns.getAllByText('object_detection')).toHaveLength(2);
    expect(aiColumns.getAllByText('pose')).toHaveLength(4);
    expect(screen.getByText(/submitted 11/i)).toBeVisible();
    expect(screen.getByText('Frame 11 / preprocess 1.2 ms / inference 3.4 ms'))
      .toBeVisible();
    expect(screen.getByText(/E_AI_POSTPROCESS.*malformed output/i)).toBeVisible();
  });

  it('renders the disabled state without model or runner rows', () => {
    render(<AiPanel ai={{ ...base, enabled: false, backend: 'disabled',
      state: 'disabled', reason: 'disabled by config', model_count: 0,
      runner_count: 0, models: [], runners: [] }} detections={{ events: [] }}
      streamStatus="connecting" onRestart={vi.fn()} />);

    expect(screen.getByText('Disabled')).toBeVisible();
    expect(screen.getByText('No AI models')).toBeVisible();
    expect(screen.getByText('No AI runners')).toBeVisible();
  });

  it('renders the live detection count and preserves multiple model results', () => {
    const { container } = renderPanel();

    expect(screen.getByText('Live')).toBeVisible();
    expect(screen.getByText('Detections 2')).toBeVisible();
    expect([...container.querySelectorAll('.detection-row')].map(
      (row) => row.textContent,
    )).toEqual(['objectscar88%', 'poseperson91%']);
  });

  it('disables restart while pending and suppresses a second click', async () => {
    const user = userEvent.setup();
    let resolve!: () => void;
    const onRestart = vi.fn(() => new Promise<void>((done) => { resolve = done; }));
    renderPanel(onRestart);
    const button = screen.getByRole('button', { name: 'Restart AI runtime' });

    await user.click(button);
    await user.click(button);
    expect(button).toBeDisabled();
    expect(onRestart).toHaveBeenCalledOnce();

    resolve();
    expect(await screen.findByRole('button', { name: 'Restart AI runtime' }))
      .toBeEnabled();
  });

  it('shows a generic restart failure and always re-enables the command', async () => {
    const user = userEvent.setup();
    const onRestart = vi.fn(async () => { throw new Error('secret server body'); });
    renderPanel(onRestart);

    await user.click(screen.getByRole('button', { name: 'Restart AI runtime' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'AI restart failed. Try again.',
    );
    expect(screen.queryByText(/secret server body/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Restart AI runtime' })).toBeEnabled();
  });
});
