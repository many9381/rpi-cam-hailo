import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import type { CameraApiClient, Parser } from '../../api/types';
import {
  DEFAULT_AUDIT_LIST_QUERY,
  type AuditEventPage,
  type AuditListQuery,
} from './contracts';
import { useAuditRecords } from './useAuditRecords';

const event = (sequence: number) => ({
  sequence,
  server_timestamp_seconds: 1_784_300_000 + sequence,
  event_type: 'viewer_disabled',
  outcome: 'success' as const,
  actor_identity: 'cameraowner',
  peer_ip: '192.0.2.10',
  detail_code: '',
  subject_type: 'user',
  subject_identity: `viewer${sequence}`,
});

const page = (sequences: number[], next_cursor: string | null): AuditEventPage => ({
  events: sequences.map(event),
  next_cursor,
});

const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
};

const makeClient = (
  response: AuditEventPage = page([1], null),
): CameraApiClient => ({
  getJson: vi.fn(async (_path: string, parser: Parser<unknown>) =>
    parser(response),
  ) as CameraApiClient['getJson'],
  deleteJson: vi.fn(),
  putJson: vi.fn(),
  postJson: vi.fn(),
  getBlob: vi.fn(),
  setUnauthorizedHandler: vi.fn(),
});

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

const lastGetPath = (client: CameraApiClient): string | undefined => {
  const calls = vi.mocked(client.getJson).mock.calls;
  return calls[calls.length - 1]?.[0];
};

describe('useAuditRecords', () => {
  it('loads the first page with a fresh exact default query', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditRecords(client));

    expect(result.current.state).toBe('loading');
    expect(result.current.query).toEqual(DEFAULT_AUDIT_LIST_QUERY);
    expect(result.current.query).not.toBe(DEFAULT_AUDIT_LIST_QUERY);
    expect(result.current.canGoBack).toBe(false);
    expect(client.getJson).toHaveBeenCalledWith(
      '/api/v1/audit/events?sort_by=timestamp&sort_direction=desc&limit=50',
      expect.any(Function),
      expect.any(AbortSignal),
    );
    await flush();

    expect(result.current.state).toBe('ready');
    expect(result.current.page?.events.map(({ sequence }) => sequence)).toEqual([1]);
  });

  it('applies filters and resets back to the first default page', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const filtered: AuditListQuery = {
      from_seconds: 100,
      event_type: 'viewer disabled',
      peer_ip: '2001:db8::1',
      sort_by: 'event_type',
      sort_direction: 'asc',
      limit: 25,
    };

    await act(async () => result.current.applyQuery(filtered));

    expect(result.current.query).toEqual(filtered);
    expect(lastGetPath(client)).toBe(
      '/api/v1/audit/events?from_seconds=100&event_type=viewer+disabled&' +
      'peer_ip=2001%3Adb8%3A%3A1&sort_by=event_type&sort_direction=asc&limit=25',
    );
    expect(result.current.canGoBack).toBe(false);

    await act(async () => result.current.applyQuery({ ...DEFAULT_AUDIT_LIST_QUERY }));

    expect(result.current.query).toEqual(DEFAULT_AUDIT_LIST_QUERY);
    expect(lastGetPath(client)).toBe(
      '/api/v1/audit/events?sort_by=timestamp&sort_direction=desc&limit=50',
    );
  });

  it('uses forward cursors and pops cursor history for previous pages', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      const cursor = new URL(path, 'https://camera.invalid').searchParams.get('cursor');
      const value = cursor === 'cursor-one'
        ? page([2], 'cursor-two')
        : cursor === 'cursor-two'
          ? page([3], null)
          : page([1], 'cursor-one');
      return parser(value);
    });
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();

    await act(async () => result.current.nextPage());
    expect(result.current.page?.events[0]?.sequence).toBe(2);
    expect(result.current.canGoBack).toBe(true);
    expect(lastGetPath(client)).toContain(
      'cursor=cursor-one',
    );

    await act(async () => result.current.nextPage());
    expect(result.current.page?.events[0]?.sequence).toBe(3);
    expect(result.current.canGoBack).toBe(true);

    await act(async () => result.current.previousPage());
    expect(result.current.page?.events[0]?.sequence).toBe(2);
    expect(result.current.canGoBack).toBe(true);
    expect(lastGetPath(client)).toContain(
      'cursor=cursor-one',
    );

    await act(async () => result.current.previousPage());
    expect(result.current.page?.events[0]?.sequence).toBe(1);
    expect(result.current.canGoBack).toBe(false);
    expect(lastGetPath(client)).not.toContain('cursor=');
  });

  it('clears cursor history when applying a new sort', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    await act(async () => result.current.nextPage());
    expect(result.current.canGoBack).toBe(true);

    await act(async () => result.current.applyQuery({
      ...result.current.query,
      sort_by: 'actor',
      sort_direction: 'asc',
    }));

    expect(result.current.canGoBack).toBe(false);
    expect(lastGetPath(client)).not.toContain('cursor=');
    expect(lastGetPath(client)).toContain(
      'sort_by=actor&sort_direction=asc',
    );
  });

  it('does not request a next page when the authoritative cursor is null', async () => {
    const client = makeClient(page([1], null));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const requestCount = vi.mocked(client.getJson).mock.calls.length;

    await act(async () => result.current.nextPage());

    expect(client.getJson).toHaveBeenCalledTimes(requestCount);
    expect(result.current.canGoBack).toBe(false);
  });

  it('does not duplicate an in-flight next transition or its cursor history', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    const firstReply = deferred<AuditEventPage>();
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    vi.mocked(client.getJson).mockReturnValueOnce(firstReply.promise);

    let firstNext!: Promise<void>;
    let duplicateNext!: Promise<void>;
    act(() => {
      firstNext = result.current.nextPage();
      duplicateNext = result.current.nextPage();
    });
    await act(async () => {
      firstReply.resolve(page([2], 'cursor-two'));
      await Promise.all([firstNext, duplicateNext]);
    });

    expect(client.getJson).toHaveBeenCalledTimes(2);
    expect(result.current.page?.events[0]?.sequence).toBe(2);
    expect(result.current.canGoBack).toBe(true);

    vi.mocked(client.getJson).mockResolvedValueOnce(page([1], 'cursor-one'));
    await act(async () => result.current.previousPage());

    expect(lastGetPath(client)).not.toContain('cursor=');
    expect(result.current.page?.events[0]?.sequence).toBe(1);
    expect(result.current.canGoBack).toBe(false);
  });

  it('does not duplicate an in-flight previous transition or pop its cursor history', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockImplementation(async (path, parser) => {
      const cursor = new URL(path, 'https://camera.invalid').searchParams.get('cursor');
      const value = cursor === 'cursor-one'
        ? page([2], 'cursor-two')
        : cursor === 'cursor-two'
          ? page([3], null)
          : page([1], 'cursor-one');
      return parser(value);
    });
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    await act(async () => result.current.nextPage());
    await act(async () => result.current.nextPage());

    const previousReply = deferred<AuditEventPage>();
    vi.mocked(client.getJson).mockReturnValueOnce(previousReply.promise);
    let firstPrevious!: Promise<void>;
    let duplicatePrevious!: Promise<void>;
    act(() => {
      firstPrevious = result.current.previousPage();
      duplicatePrevious = result.current.previousPage();
    });

    expect(client.getJson).toHaveBeenCalledTimes(4);

    await act(async () => {
      previousReply.resolve(page([2], 'cursor-two'));
      await Promise.all([firstPrevious, duplicatePrevious]);
    });

    expect(lastGetPath(client)).toContain('cursor=cursor-one');
    expect(result.current.page?.events[0]?.sequence).toBe(2);
    expect(result.current.canGoBack).toBe(true);

    await act(async () => result.current.previousPage());

    expect(lastGetPath(client)).not.toContain('cursor=');
    expect(result.current.page?.events[0]?.sequence).toBe(1);
    expect(result.current.canGoBack).toBe(false);
  });

  it('retains history after a failed previous transition and retries the exact prior page', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    vi.mocked(client.getJson).mockResolvedValueOnce(page([2], null));
    await act(async () => result.current.nextPage());
    const retainedPage = result.current.page;
    const failed = deferred<AuditEventPage>();
    vi.mocked(client.getJson).mockReturnValueOnce(failed.promise);

    let previous!: Promise<void>;
    act(() => {
      previous = result.current.previousPage();
    });
    await act(async () => {
      failed.reject(new Error('page one unavailable'));
      await expect(previous).rejects.toThrow('page one unavailable');
    });

    expect(result.current.state).toBe('stale');
    expect(result.current.page).toBe(retainedPage);
    expect(result.current.canGoBack).toBe(true);

    vi.mocked(client.getJson).mockResolvedValueOnce(page([1], 'cursor-one'));
    await act(async () => result.current.previousPage());

    expect(lastGetPath(client)).not.toContain('cursor=');
    expect(result.current.page?.events[0]?.sequence).toBe(1);
    expect(result.current.canGoBack).toBe(false);
  });

  it('retains committed rows and navigation after a next transition fails', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const retainedPage = result.current.page;
    const retainedQuery = result.current.query;
    const failed = deferred<AuditEventPage>();
    vi.mocked(client.getJson).mockReturnValueOnce(failed.promise);

    let next!: Promise<void>;
    act(() => {
      next = result.current.nextPage();
    });
    await act(async () => {
      failed.reject(new Error('page two unavailable'));
      await expect(next).rejects.toThrow('page two unavailable');
    });

    expect(result.current.state).toBe('stale');
    expect(result.current.page).toBe(retainedPage);
    expect(result.current.query).toBe(retainedQuery);
    expect(result.current.canGoBack).toBe(false);
    const requestCount = vi.mocked(client.getJson).mock.calls.length;

    await act(async () => result.current.previousPage());
    expect(client.getJson).toHaveBeenCalledTimes(requestCount);

    vi.mocked(client.getJson).mockResolvedValueOnce(page([2], 'cursor-two'));
    await act(async () => result.current.nextPage());

    expect(lastGetPath(client)).toContain('cursor=cursor-one');
    expect(result.current.page?.events[0]?.sequence).toBe(2);
    expect(result.current.canGoBack).toBe(true);
  });

  it('retains committed query and history after an apply transition fails', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    vi.mocked(client.getJson).mockResolvedValueOnce(page([2], 'cursor-two'));
    await act(async () => result.current.nextPage());
    const retainedPage = result.current.page;
    const retainedQuery = result.current.query;
    const failed = deferred<AuditEventPage>();
    vi.mocked(client.getJson).mockReturnValueOnce(failed.promise);

    let apply!: Promise<void>;
    act(() => {
      apply = result.current.applyQuery({
        ...DEFAULT_AUDIT_LIST_QUERY,
        event_type: 'failed-filter',
      });
    });
    await act(async () => {
      failed.reject(new Error('filter unavailable'));
      await expect(apply).rejects.toThrow('filter unavailable');
    });

    expect(result.current.state).toBe('stale');
    expect(result.current.page).toBe(retainedPage);
    expect(result.current.query).toBe(retainedQuery);
    expect(result.current.canGoBack).toBe(true);

    vi.mocked(client.getJson).mockResolvedValueOnce(page([1], 'cursor-one'));
    await act(async () => result.current.previousPage());

    expect(lastGetPath(client)).not.toContain('event_type=failed-filter');
    expect(lastGetPath(client)).not.toContain('cursor=');
    expect(result.current.page?.events[0]?.sequence).toBe(1);
    expect(result.current.canGoBack).toBe(false);
  });

  it('ignores mixed navigation and refresh while an apply transition is active', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const applied = deferred<AuditEventPage>();
    vi.mocked(client.getJson).mockReturnValueOnce(applied.promise);
    const filtered = { ...DEFAULT_AUDIT_LIST_QUERY, event_type: 'filtered' };

    let apply!: Promise<void>;
    let next!: Promise<void>;
    let previous!: Promise<void>;
    let refresh!: Promise<void>;
    act(() => {
      apply = result.current.applyQuery(filtered);
      next = result.current.nextPage();
      previous = result.current.previousPage();
      refresh = result.current.refresh();
    });
    await act(async () => {
      applied.resolve(page([9], null));
      await Promise.all([apply, next, previous, refresh]);
    });

    expect(client.getJson).toHaveBeenCalledTimes(2);
    expect(result.current.state).toBe('ready');
    expect(result.current.page?.events[0]?.sequence).toBe(9);
    expect(result.current.query).toEqual(filtered);
    expect(result.current.canGoBack).toBe(false);
  });

  it('allows apply query to supersede an in-flight next transition', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const navigating = deferred<AuditEventPage>();
    const applying = deferred<AuditEventPage>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(navigating.promise)
      .mockReturnValueOnce(applying.promise);
    const filtered = { ...DEFAULT_AUDIT_LIST_QUERY, event_type: 'filtered' };

    let next!: Promise<void>;
    let apply!: Promise<void>;
    act(() => {
      next = result.current.nextPage();
      apply = result.current.applyQuery(filtered);
    });
    const calls = vi.mocked(client.getJson).mock.calls;
    expect(calls[calls.length - 2]?.[2]?.aborted).toBe(true);
    expect(calls[calls.length - 1]?.[2]?.aborted).toBe(false);

    await act(async () => {
      applying.resolve(page([9], null));
      await apply;
    });
    await act(async () => {
      navigating.reject(new Error('late navigation failure'));
      await expect(next).resolves.toBeUndefined();
    });

    expect(result.current.state).toBe('ready');
    expect(result.current.page?.events[0]?.sequence).toBe(9);
    expect(result.current.query).toEqual(filtered);
    expect(result.current.canGoBack).toBe(false);
  });

  it('aborts superseded loads and ignores their late responses', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const older = deferred<AuditEventPage>();
    const newer = deferred<AuditEventPage>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);
    const olderQuery = { ...DEFAULT_AUDIT_LIST_QUERY, event_type: 'older' };
    const newerQuery = { ...DEFAULT_AUDIT_LIST_QUERY, event_type: 'newer' };

    let olderLoad!: Promise<void>;
    let newerLoad!: Promise<void>;
    act(() => {
      olderLoad = result.current.applyQuery(olderQuery);
      newerLoad = result.current.applyQuery(newerQuery);
    });
    const calls = vi.mocked(client.getJson).mock.calls;
    expect(calls[calls.length - 2]?.[2]?.aborted).toBe(true);
    expect(calls[calls.length - 1]?.[2]?.aborted).toBe(false);

    await act(async () => {
      newer.resolve(page([9], null));
      await newerLoad;
    });
    await act(async () => {
      older.resolve(page([8], null));
      await olderLoad;
    });

    expect(result.current.query).toEqual(newerQuery);
    expect(result.current.page?.events[0]?.sequence).toBe(9);
  });

  it('ignores an older late rejection after a newer query succeeds', async () => {
    const client = makeClient();
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const older = deferred<AuditEventPage>();
    const newer = deferred<AuditEventPage>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);
    const olderQuery = { ...DEFAULT_AUDIT_LIST_QUERY, event_type: 'older' };
    const newerQuery = { ...DEFAULT_AUDIT_LIST_QUERY, event_type: 'newer' };

    let olderLoad!: Promise<void>;
    let newerLoad!: Promise<void>;
    act(() => {
      olderLoad = result.current.applyQuery(olderQuery);
      newerLoad = result.current.applyQuery(newerQuery);
    });
    await act(async () => {
      newer.resolve(page([9], null));
      await newerLoad;
    });
    await act(async () => {
      older.reject(new Error('late private failure'));
      await expect(olderLoad).resolves.toBeUndefined();
    });

    expect(result.current.state).toBe('ready');
    expect(result.current.query).toEqual(newerQuery);
    expect(result.current.page?.events[0]?.sequence).toBe(9);
  });

  it('retains the committed page when the authoritative newer query fails', async () => {
    const client = makeClient(page([1], 'cursor-one'));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const retainedPage = result.current.page;
    const retainedQuery = result.current.query;
    const older = deferred<AuditEventPage>();
    const newer = deferred<AuditEventPage>();
    vi.mocked(client.getJson)
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise);
    const olderQuery = { ...DEFAULT_AUDIT_LIST_QUERY, event_type: 'older' };
    const newerQuery = { ...DEFAULT_AUDIT_LIST_QUERY, event_type: 'newer' };

    let olderLoad!: Promise<void>;
    let newerLoad!: Promise<void>;
    act(() => {
      olderLoad = result.current.applyQuery(olderQuery);
      newerLoad = result.current.applyQuery(newerQuery);
    });
    await act(async () => {
      older.resolve(page([8], null));
      await olderLoad;
    });
    await act(async () => {
      newer.reject(new Error('newest query failed'));
      await expect(newerLoad).rejects.toThrow('newest query failed');
    });

    expect(result.current.state).toBe('stale');
    expect(result.current.page).toBe(retainedPage);
    expect(result.current.query).toBe(retainedQuery);
    expect(result.current.canGoBack).toBe(false);
  });

  it('aborts an active event request when the panel unmounts', async () => {
    const client = makeClient();
    const pending = deferred<AuditEventPage>();
    vi.mocked(client.getJson).mockReturnValue(pending.promise);
    const { unmount } = renderHook(() => useAuditRecords(client));
    const signal = vi.mocked(client.getJson).mock.calls[0]?.[2];
    const onAbort = vi.fn();
    signal?.addEventListener('abort', onAbort);

    unmount();

    expect(signal?.aborted).toBe(true);
    expect(onAbort).toHaveBeenCalledOnce();
    await act(async () => pending.reject(new DOMException('Aborted', 'AbortError')));
  });

  it('retains stale rows after a refresh failure', async () => {
    const client = makeClient(page([4, 5], null));
    const { result } = renderHook(() => useAuditRecords(client));
    await flush();
    const retained = result.current.page;
    const failed = deferred<AuditEventPage>();
    vi.mocked(client.getJson).mockReturnValueOnce(failed.promise);

    let refresh!: Promise<void>;
    act(() => {
      refresh = result.current.refresh();
    });
    expect(result.current.state).toBe('refreshing');
    expect(result.current.page).toBe(retained);

    await act(async () => {
      failed.reject(new Error('private store failure'));
      await expect(refresh).rejects.toThrow('private store failure');
    });

    expect(result.current.state).toBe('stale');
    expect(result.current.page).toBe(retained);
  });

  it('reports unavailable when the initial page cannot load', async () => {
    const client = makeClient();
    vi.mocked(client.getJson).mockRejectedValue(new Error('offline'));
    const { result } = renderHook(() => useAuditRecords(client));

    await flush();

    expect(result.current.state).toBe('unavailable');
    expect(result.current.page).toBeNull();
  });
});
