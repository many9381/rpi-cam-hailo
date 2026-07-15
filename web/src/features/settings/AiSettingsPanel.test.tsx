import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import { AiSettingsPanel } from './AiSettingsPanel';
import { makeSettingsController, makeSettingsSnapshot } from './testSupport';

afterEach(cleanup);

describe('AiSettingsPanel', () => {
  it('renders one enable switch and synchronized confidence controls per model', () => {
    const controller = makeSettingsController();
    render(<AiSettingsPanel controller={controller} />);

    expect(screen.getAllByRole('switch')).toHaveLength(2);
    expect(screen.getByRole('switch', { name: 'objects enabled' })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'pose enabled' })).not.toBeChecked();
    expect(screen.getAllByRole('slider')).toHaveLength(2);
    expect(screen.getAllByRole('spinbutton')).toHaveLength(2);
    expect(screen.getByRole('slider', { name: 'objects confidence' })).toHaveValue('0.4');
    expect(screen.getByRole('spinbutton', { name: 'objects confidence value' }))
      .toHaveValue(0.4);
  });

  it('shows only safe read-only model capabilities', () => {
    const snapshot = makeSettingsSnapshot();
    Object.assign(snapshot.capabilities.models[0] as unknown as Record<string, unknown>, {
      hef_path: '/opt/models/private-object.hef',
      output_name: 'private_output0',
    });
    render(<AiSettingsPanel controller={makeSettingsController({ snapshot })} />);

    expect(screen.getByText('object_detection')).toBeVisible();
    expect(screen.getAllByText('640 x 640')).toHaveLength(2);
    expect(screen.getAllByText('RGB')).toHaveLength(2);
    expect(screen.getAllByText('Letterbox')).toHaveLength(2);
    expect(screen.getByText('coco80')).toBeVisible();
    expect(screen.queryByText('/opt/models/private-object.hef')).not.toBeInTheDocument();
    expect(screen.queryByText('private_output0')).not.toBeInTheDocument();
  });

  it('updates model enablement and confidence by stable model ID', () => {
    const controller = makeSettingsController();
    render(<AiSettingsPanel controller={controller} />);

    fireEvent.click(screen.getByRole('switch', { name: 'objects enabled' }));
    expect(controller.updateModel).toHaveBeenLastCalledWith('objects', {
      enabled: false,
    });

    fireEvent.change(screen.getByRole('slider', { name: 'pose confidence' }), {
      target: { value: '0.65' },
    });
    expect(controller.updateModel).toHaveBeenLastCalledWith('pose', {
      confidence_threshold: 0.65,
    });

    fireEvent.change(screen.getByRole('spinbutton', {
      name: 'objects confidence value',
    }), { target: { value: '0.55' } });
    expect(controller.updateModel).toHaveBeenLastCalledWith('objects', {
      confidence_threshold: 0.55,
    });
  });

  it('disables all model controls while saving or applying', () => {
    const snapshot = makeSettingsSnapshot();
    const controller = makeSettingsController({
      status: 'saving', snapshot, draft: snapshot.active,
    });
    render(<AiSettingsPanel controller={controller} />);

    for (const control of [
      ...screen.getAllByRole('switch'),
      ...screen.getAllByRole('slider'),
      ...screen.getAllByRole('spinbutton'),
    ]) {
      expect(control).toBeDisabled();
    }
  });
});
