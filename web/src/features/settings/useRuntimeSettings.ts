import { useCallback, useEffect, useRef, useState } from 'react';

import { ApiError, UnauthorizedError } from '../../api/client';
import type { CameraApiClient } from '../../api/types';
import {
  isRuntimeSettingsErrorCode,
  osdSettingsEqual,
  parseRuntimeSettingsApplyResponse,
  parseRuntimeSettingsSnapshot,
  type CameraRuntimeSettings,
  type ModelRuntimeSettings,
  type OsdRuntimeSettings,
  type PublicApiError,
  type RuntimeSettings,
  type RuntimeSettingsSnapshot,
  type SubStreamRuntimeSettings,
} from './contracts';

export interface RuntimeSettingsController {
  status: 'loading' | 'ready' | 'saving' | 'applying' | 'error';
  snapshot: RuntimeSettingsSnapshot | null;
  draft: RuntimeSettings | null;
  dirty: boolean;
  error: PublicApiError | null;
  updateCamera(next: CameraRuntimeSettings): void;
  updateSubStream(next: SubStreamRuntimeSettings): void;
  updateOsd(next: OsdRuntimeSettings): void;
  updateModel(id: string, patch: Partial<ModelRuntimeSettings>): void;
  save(): Promise<void>;
  apply(): Promise<void>;
  discard(): Promise<void>;
  refresh(): Promise<void>;
}

const preferredSettings = (snapshot: RuntimeSettingsSnapshot): RuntimeSettings =>
  snapshot.pending ?? snapshot.active;

const settingsEqual = (
  left: RuntimeSettings | null,
  right: RuntimeSettings | null,
): boolean => {
  if (left === null || right === null) {
    return left === right;
  }
  return left.camera.profile_id === right.camera.profile_id &&
    left.camera.bitrate_kbps === right.camera.bitrate_kbps &&
    left.camera.gop === right.camera.gop &&
    left.sub_stream.enabled === right.sub_stream.enabled &&
    left.sub_stream.width === right.sub_stream.width &&
    left.sub_stream.height === right.sub_stream.height &&
    left.sub_stream.fps === right.sub_stream.fps &&
    left.sub_stream.bitrate_kbps === right.sub_stream.bitrate_kbps &&
    osdSettingsEqual(left.osd, right.osd) &&
    left.models.length === right.models.length &&
    left.models.every((model, index) => {
      const other = right.models[index];
      return other !== undefined && model.id === other.id &&
        model.enabled === other.enabled &&
        model.confidence_threshold === other.confidence_threshold;
    });
};

const toPublicError = (error: unknown): PublicApiError => {
  if (error instanceof ApiError) {
    return {
      status: error.status,
      code: isRuntimeSettingsErrorCode(error.code)
        ? error.code
        : 'E_SETTINGS_REQUEST_FAILED',
    };
  }
  return { status: 0, code: 'E_SETTINGS_REQUEST_FAILED' };
};

export function useRuntimeSettings(
  client: CameraApiClient,
): RuntimeSettingsController {
  const [status, setStatus] = useState<RuntimeSettingsController['status']>('loading');
  const [snapshot, setSnapshot] = useState<RuntimeSettingsSnapshot | null>(null);
  const [draft, setDraft] = useState<RuntimeSettings | null>(null);
  const [error, setError] = useState<PublicApiError | null>(null);
  const mounted = useRef(true);
  const snapshotRef = useRef<RuntimeSettingsSnapshot | null>(null);
  const draftRef = useRef<RuntimeSettings | null>(null);
  const refreshGeneration = useRef(0);
  const activeRefresh = useRef<AbortController | null>(null);
  const activeCommand = useRef<AbortController | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      refreshGeneration.current += 1;
      activeRefresh.current?.abort();
      activeCommand.current?.abort();
    };
  }, []);

  const replaceDraft = useCallback((next: RuntimeSettings | null) => {
    draftRef.current = next;
    setDraft(next);
  }, []);

  const adoptSnapshot = useCallback((
    next: RuntimeSettingsSnapshot,
    preserveDirtyDraft: boolean,
  ): boolean => {
    const previousSnapshot = snapshotRef.current;
    if (previousSnapshot !== null && next.revision < previousSnapshot.revision) {
      return false;
    }
    const previousDraft = draftRef.current;
    const previousBase = previousSnapshot === null
      ? null
      : preferredSettings(previousSnapshot);
    const keepDraft = preserveDirtyDraft && previousDraft !== null &&
      !settingsEqual(previousDraft, previousBase);
    snapshotRef.current = next;
    setSnapshot(next);
    replaceDraft(keepDraft ? previousDraft : preferredSettings(next));
    return true;
  }, [replaceDraft]);

  const loadSnapshot = useCallback(async (preserveDirtyDraft: boolean) => {
    const generation = refreshGeneration.current + 1;
    refreshGeneration.current = generation;
    activeRefresh.current?.abort();
    const controller = new AbortController();
    activeRefresh.current = controller;
    if (snapshotRef.current === null && mounted.current) {
      setStatus('loading');
    }
    try {
      const next = await client.getJson(
        '/api/v1/settings/runtime',
        parseRuntimeSettingsSnapshot,
        controller.signal,
      );
      if (!mounted.current || generation !== refreshGeneration.current) {
        return;
      }
      if (adoptSnapshot(
        parseRuntimeSettingsSnapshot(next),
        preserveDirtyDraft,
      )) {
        if (activeCommand.current === null) {
          setError(null);
          setStatus('ready');
        }
      }
    } catch (caught) {
      if (mounted.current && generation === refreshGeneration.current &&
          activeCommand.current === null) {
        setError(toPublicError(caught));
        setStatus('error');
      }
      throw caught;
    } finally {
      if (activeRefresh.current === controller) {
        activeRefresh.current = null;
      }
    }
  }, [adoptSnapshot, client]);

  useEffect(() => {
    void loadSnapshot(false).catch(() => undefined);
  }, [loadSnapshot]);

  const handleCommandError = useCallback(async (caught: unknown) => {
    const publicError = toPublicError(caught);
    const shouldRefresh = caught instanceof ApiError &&
      !(caught instanceof UnauthorizedError) &&
      (caught.code === 'E_SETTINGS_REVISION_CONFLICT' ||
       caught.code === 'E_SETTINGS_NO_PENDING' ||
       caught.code === 'E_SETTINGS_APPLY_FAILED');
    if (shouldRefresh) {
      try {
        await loadSnapshot(true);
      } catch {
        // The original bounded command error remains authoritative.
      }
    }
    if (mounted.current) {
      setError(publicError);
      setStatus('error');
    }
  }, [loadSnapshot]);

  const beginCommand = useCallback((
    nextStatus: 'saving' | 'applying',
  ): AbortController | null => {
    if (activeCommand.current !== null) {
      return null;
    }
    const controller = new AbortController();
    activeCommand.current = controller;
    setError(null);
    setStatus(nextStatus);
    return controller;
  }, []);

  const finishCommand = useCallback((controller: AbortController) => {
    if (activeCommand.current === controller) {
      activeCommand.current = null;
    }
  }, []);

  const save = useCallback(async () => {
    const currentSnapshot = snapshotRef.current;
    const currentDraft = draftRef.current;
    if (currentSnapshot === null || currentDraft === null) {
      return;
    }
    const controller = beginCommand('saving');
    if (controller === null) {
      return;
    }
    try {
      const next = await client.putJson(
        '/api/v1/settings/runtime',
        { expected_revision: currentSnapshot.revision, settings: currentDraft },
        parseRuntimeSettingsSnapshot,
        controller.signal,
      );
      if (mounted.current) {
        adoptSnapshot(next, false);
        setStatus('ready');
      }
    } catch (caught) {
      await handleCommandError(caught);
    } finally {
      finishCommand(controller);
    }
  }, [adoptSnapshot, beginCommand, client, finishCommand, handleCommandError]);

  const apply = useCallback(async () => {
    const currentSnapshot = snapshotRef.current;
    if (currentSnapshot === null) {
      return;
    }
    const controller = beginCommand('applying');
    if (controller === null) {
      return;
    }
    try {
      const result = await client.postJson(
        '/api/v1/settings/runtime/apply',
        { expected_revision: currentSnapshot.revision },
        parseRuntimeSettingsApplyResponse,
        controller.signal,
      );
      if (mounted.current) {
        adoptSnapshot(result.snapshot, false);
        setStatus('ready');
      }
    } catch (caught) {
      await handleCommandError(caught);
    } finally {
      finishCommand(controller);
    }
  }, [adoptSnapshot, beginCommand, client, finishCommand, handleCommandError]);

  const discard = useCallback(async () => {
    const currentSnapshot = snapshotRef.current;
    if (currentSnapshot === null) {
      return;
    }
    const controller = beginCommand('saving');
    if (controller === null) {
      return;
    }
    try {
      const next = await client.postJson(
        '/api/v1/settings/runtime/discard',
        { expected_revision: currentSnapshot.revision },
        parseRuntimeSettingsSnapshot,
        controller.signal,
      );
      if (mounted.current) {
        adoptSnapshot(next, false);
        setStatus('ready');
      }
    } catch (caught) {
      await handleCommandError(caught);
    } finally {
      finishCommand(controller);
    }
  }, [adoptSnapshot, beginCommand, client, finishCommand, handleCommandError]);

  const updateCamera = useCallback((next: CameraRuntimeSettings) => {
    const current = draftRef.current;
    if (current === null) {
      return;
    }
    replaceDraft({ ...current, camera: next });
  }, [replaceDraft]);

  const updateSubStream = useCallback((next: SubStreamRuntimeSettings) => {
    const current = draftRef.current;
    if (current === null) {
      return;
    }
    replaceDraft({ ...current, sub_stream: next });
  }, [replaceDraft]);

  const updateOsd = useCallback((next: OsdRuntimeSettings) => {
    const current = draftRef.current;
    if (current === null) {
      return;
    }
    replaceDraft({ ...current, osd: next });
  }, [replaceDraft]);

  const updateModel = useCallback((
    id: string,
    patch: Partial<ModelRuntimeSettings>,
  ) => {
    const current = draftRef.current;
    if (current === null || !current.models.some((model) => model.id === id)) {
      return;
    }
    replaceDraft({
      ...current,
      models: current.models.map((model) => model.id === id
        ? { ...model, ...patch, id: model.id }
        : model),
    });
  }, [replaceDraft]);

  return {
    status,
    snapshot,
    draft,
    dirty: !settingsEqual(draft, snapshot === null ? null : preferredSettings(snapshot)),
    error,
    updateCamera,
    updateSubStream,
    updateOsd,
    updateModel,
    save,
    apply,
    discard,
    refresh: useCallback(() => loadSnapshot(true), [loadSnapshot]),
  };
}
