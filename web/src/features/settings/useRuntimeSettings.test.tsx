import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { ApiError, UnauthorizedError } from '../../api/client';
import type { CameraApiClient, Parser } from '../../api/types';
import type { RuntimeSettings, RuntimeSettingsSnapshot } from './contracts';
import { useRuntimeSettings } from './useRuntimeSettings';

const settings = (
  profileId = 'imx708-1080p50',
  bitrateKbps = 6_000,
): RuntimeSettings => ({
  camera: { profile_id: profileId, bitrate_kbps: bitrateKbps, gop: 25 },
  sub_stream: {
    enabled: false, width: 640, height: 360, fps: 15, bitrate_kbps: 1_000,
  },
  osd: { enabled: false, items: [] },
  models: [
    { id: 'objects', enabled: true, confidence_threshold: 0.4 },
    { id: 'pose', enabled: false, confidence_threshold: 0.5 },
  ],
});

const snapshot = (
  revision = 1,
  pending: ReturnType<typeof settings> | null = null,
): RuntimeSettingsSnapshot => ({
  schema_version: 1,
  revision,
  state: pending === null ? 'clean' : 'pending',
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
      { id: 'objects', kind: 'object_detection', input_width: 640,
        input_height: 640, input_format: 'rgb', letterbox: true, labels: 'coco80' },
      { id: 'pose', kind: 'pose', input_width: 640, input_height: 640,
        input_format: 'rgb', letterbox: true, labels: 'pose17' },
    ],
  },
  active: settings(),
  pending,
  last_apply: { status: 'never', code: '', restored: false },
});

const parseWith = <T,>(parser: Parser<T>, value: unknown): T => parser(value);

const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
};

const makeClient = (initial = snapshot()) => {
  let current = initial;
  const client = {
    getJson: vi.fn(async (_path: string, parser: Parser<unknown>) =>
      parseWith(parser, current)),
    putJson: vi.fn(async (_path: string, _body: unknown, parser: Parser<unknown>) =>
      parseWith(parser, current)),
    postJson: vi.fn(async (_path: string, _body: unknown, parser: Parser<unknown>) =>
      parseWith(parser, current)),
    getBlob: vi.fn(),
    setUnauthorizedHandler: vi.fn(),
  } as unknown as CameraApiClient;
  return {
    client,
    setCurrent(next: RuntimeSettingsSnapshot) {
      current = next;
    },
  };
};

describe('useRuntimeSettings', () => {
  it('loads the server pending snapshot as the stable shared draft', async () => {
    const pending = settings('imx708-720p50', 5_000);
    const { client } = makeClient(snapshot(3, pending));
    const { result, rerender } = renderHook(() => useRuntimeSettings(client));

    await waitFor(() => expect(result.current.status).toBe('ready'));
    expect(result.current.snapshot?.revision).toBe(3);
    expect(result.current.draft).toEqual(pending);
    expect(result.current.dirty).toBe(false);

    rerender();
    expect(client.getJson).toHaveBeenCalledTimes(1);
    expect(result.current.draft).toEqual(pending);
  });

  it('updates camera and model draft values without mutating the server snapshot', async () => {
    const { client } = makeClient();
    const { result } = renderHook(() => useRuntimeSettings(client));
    await waitFor(() => expect(result.current.status).toBe('ready'));

    act(() => {
      result.current.updateCamera({
        profile_id: 'imx708-720p50', bitrate_kbps: 5_500, gop: 30,
      });
      result.current.updateModel('objects', {
        enabled: false,
        confidence_threshold: 0.55,
      });
    });

    expect(result.current.dirty).toBe(true);
    expect(result.current.draft?.camera.profile_id).toBe('imx708-720p50');
    expect(result.current.draft?.models[0]).toEqual({
      id: 'objects', enabled: false, confidence_threshold: 0.55,
    });
    expect(result.current.snapshot?.active).toEqual(settings());
  });

  it('updates sub_stream draft values and marks the draft dirty', async () => {
    const { client } = makeClient();
    const { result } = renderHook(() => useRuntimeSettings(client));
    await waitFor(() => expect(result.current.status).toBe('ready'));

    act(() => {
      result.current.updateSubStream({
        enabled: true, width: 854, height: 480, fps: 24, bitrate_kbps: 1_500,
      });
    });

    expect(result.current.dirty).toBe(true);
    expect(result.current.draft?.sub_stream).toEqual({
      enabled: true, width: 854, height: 480, fps: 24, bitrate_kbps: 1_500,
    });
    expect(result.current.snapshot?.active).toEqual(settings());
  });

  it('saves a full draft with the expected revision and adopts returned pending state', async () => {
    const { client } = makeClient();
    const { result } = renderHook(() => useRuntimeSettings(client));
    await waitFor(() => expect(result.current.status).toBe('ready'));
    act(() => result.current.updateCamera({
      profile_id: 'imx708-720p50', bitrate_kbps: 5_000, gop: 30,
    }));
    const edited = result.current.draft!;
    const saved = snapshot(2, edited);
    vi.mocked(client.putJson).mockImplementation(async (_path, _body, parser) =>
      parser(saved));

    await act(async () => result.current.save());

    expect(client.putJson).toHaveBeenCalledWith(
      '/api/v1/settings/runtime',
      { expected_revision: 1, settings: edited },
      expect.any(Function),
      expect.any(AbortSignal),
    );
    expect(result.current.snapshot).toEqual(saved);
    expect(result.current.draft).toEqual(edited);
    expect(result.current.dirty).toBe(false);
    expect(result.current.status).toBe('ready');
  });

  it('applies and discards with revision-only commands', async () => {
    const pending = settings('imx708-720p50', 5_000);
    const { client } = makeClient(snapshot(5, pending));
    const { result } = renderHook(() => useRuntimeSettings(client));
    await waitFor(() => expect(result.current.status).toBe('ready'));
    const applied = { ...snapshot(6), active: pending };
    vi.mocked(client.postJson).mockImplementationOnce(
      async (_path, _body, parser) => parser({
        ...applied, applied: true, restored: false,
      }),
    );

    await act(async () => result.current.apply());

    expect(client.postJson).toHaveBeenNthCalledWith(
      1,
      '/api/v1/settings/runtime/apply',
      { expected_revision: 5 },
      expect.any(Function),
      expect.any(AbortSignal),
    );
    expect(result.current.snapshot?.active).toEqual(pending);
    expect(result.current.draft).toEqual(pending);

    const nextPending = settings('imx708-1080p50', 7_000);
    const pendingAgain = { ...snapshot(7, nextPending), active: pending };
    await act(async () => {
      vi.mocked(client.getJson).mockImplementationOnce(async (_path, parser) =>
        parser(pendingAgain));
      await result.current.refresh();
    });
    const discarded = { ...snapshot(8), active: pending };
    vi.mocked(client.postJson).mockImplementationOnce(
      async (_path, _body, parser) => parser(discarded),
    );

    await act(async () => result.current.discard());

    expect(client.postJson).toHaveBeenNthCalledWith(
      2,
      '/api/v1/settings/runtime/discard',
      { expected_revision: 7 },
      expect.any(Function),
      expect.any(AbortSignal),
    );
    expect(result.current.snapshot).toEqual(discarded);
    expect(result.current.draft).toEqual(pending);
    expect(result.current.dirty).toBe(false);
  });

  it('refreshes a revision conflict without overwriting the local draft', async () => {
    const { client, setCurrent } = makeClient();
    const { result } = renderHook(() => useRuntimeSettings(client));
    await waitFor(() => expect(result.current.status).toBe('ready'));
    act(() => result.current.updateCamera({
      profile_id: 'imx708-720p50', bitrate_kbps: 5_500, gop: 30,
    }));
    const localDraft = result.current.draft!;
    const serverPending = settings('imx708-1080p50', 8_000);
    setCurrent(snapshot(2, serverPending));
    vi.mocked(client.putJson).mockRejectedValueOnce(
      new ApiError(409, 'E_SETTINGS_REVISION_CONFLICT'),
    );

    await act(async () => result.current.save());

    expect(result.current.snapshot?.revision).toBe(2);
    expect(result.current.snapshot?.pending).toEqual(serverPending);
    expect(result.current.draft).toEqual(localDraft);
    expect(result.current.dirty).toBe(true);
    expect(result.current.status).toBe('error');
    expect(result.current.error).toEqual({
      status: 409,
      code: 'E_SETTINGS_REVISION_CONFLICT',
    });
  });

  it('does not let an older refresh roll back a completed save', async () => {
    const { client } = makeClient();
    const { result } = renderHook(() => useRuntimeSettings(client));
    await waitFor(() => expect(result.current.status).toBe('ready'));
    const staleRefresh = deferred<RuntimeSettingsSnapshot>();
    vi.mocked(client.getJson).mockImplementationOnce(async (_path, parser) =>
      parser(await staleRefresh.promise));
    const refresh = result.current.refresh();

    act(() => result.current.updateCamera({
      profile_id: 'imx708-720p50', bitrate_kbps: 5_000, gop: 30,
    }));
    const saved = snapshot(2, result.current.draft!);
    vi.mocked(client.putJson).mockImplementationOnce(async (_path, _body, parser) =>
      parser(saved));
    await act(async () => result.current.save());

    await act(async () => {
      staleRefresh.resolve(snapshot(1));
      await refresh;
    });

    expect(result.current.snapshot).toEqual(saved);
    expect(result.current.draft).toEqual(saved.pending);
    expect(result.current.dirty).toBe(false);
  });

  it('keeps a command busy while a concurrent refresh settles', async () => {
    const { client } = makeClient();
    const { result } = renderHook(() => useRuntimeSettings(client));
    await waitFor(() => expect(result.current.status).toBe('ready'));
    act(() => result.current.updateCamera({
      profile_id: 'imx708-720p50', bitrate_kbps: 5_000, gop: 30,
    }));
    const saveResponse = deferred<RuntimeSettingsSnapshot>();
    vi.mocked(client.putJson).mockImplementationOnce(async (_path, _body, parser) =>
      parser(await saveResponse.promise));

    let save!: Promise<void>;
    act(() => {
      save = result.current.save();
    });
    await waitFor(() => expect(result.current.status).toBe('saving'));

    await act(async () => result.current.refresh());

    expect(result.current.status).toBe('saving');
    await act(async () => {
      saveResponse.resolve(snapshot(2, result.current.draft));
      await save;
    });
    expect(result.current.status).toBe('ready');
  });

  it('leaves session expiration to the API client authentication flow', async () => {
    const { client } = makeClient();
    const { result } = renderHook(() => useRuntimeSettings(client));
    await waitFor(() => expect(result.current.status).toBe('ready'));
    act(() => result.current.updateCamera({
      profile_id: 'imx708-720p50', bitrate_kbps: 5_000, gop: 30,
    }));
    vi.mocked(client.putJson).mockRejectedValueOnce(
      new UnauthorizedError('E_SESSION_EXPIRED'),
    );

    await act(async () => result.current.save());

    expect(client.getJson).toHaveBeenCalledTimes(1);
    expect(result.current.status).toBe('error');
    expect(result.current.error).toEqual({
      status: 401,
      code: 'E_SETTINGS_REQUEST_FAILED',
    });
  });

  it('rejects a client response that bypasses the strict parser without corrupting state', async () => {
    const { client } = makeClient();
    vi.mocked(client.getJson).mockResolvedValueOnce(undefined as never);

    const { result } = renderHook(() => useRuntimeSettings(client));

    await waitFor(() => expect(result.current.status).toBe('error'));
    expect(result.current.snapshot).toBeNull();
    expect(result.current.draft).toBeNull();
    expect(result.current.error).toEqual({
      status: 0,
      code: 'E_SETTINGS_REQUEST_FAILED',
    });
  });
});
