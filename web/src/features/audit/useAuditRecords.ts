import { useCallback, useEffect, useRef, useState } from 'react';

import type { CameraApiClient } from '../../api/types';
import {
  DEFAULT_AUDIT_LIST_QUERY,
  buildAuditEventsUrl,
  parseAuditEventPage,
  type AuditEventPage,
  type AuditListQuery,
} from './contracts';

export interface AuditRecordsController {
  state: 'loading' | 'ready' | 'refreshing' | 'stale' | 'unavailable';
  page: AuditEventPage | null;
  query: AuditListQuery;
  canGoBack: boolean;
  applyQuery(query: AuditListQuery): Promise<void>;
  refresh(): Promise<void>;
  nextPage(): Promise<void>;
  previousPage(): Promise<void>;
}

type Cursor = string | undefined;

const defaultQuery = (): AuditListQuery => ({ ...DEFAULT_AUDIT_LIST_QUERY });

export function useAuditRecords(client: CameraApiClient): AuditRecordsController {
  const initialQuery = useRef(defaultQuery());
  const [state, setState] = useState<AuditRecordsController['state']>('loading');
  const [page, setPage] = useState<AuditEventPage | null>(null);
  const [query, setQuery] = useState<AuditListQuery>(initialQuery.current);
  const [canGoBack, setCanGoBack] = useState(false);
  const mounted = useRef(true);
  const pageRef = useRef<AuditEventPage | null>(null);
  const queryRef = useRef<AuditListQuery>(initialQuery.current);
  const cursorRef = useRef<Cursor>(undefined);
  const cursorHistoryRef = useRef<Cursor[]>([]);
  const generationRef = useRef(0);
  const activeRequest = useRef<AbortController | null>(null);

  const loadPage = useCallback(async (
    requestedQuery: Readonly<AuditListQuery>,
    cursor: Cursor,
    cursorHistory: readonly Cursor[],
  ) => {
    if (!mounted.current) {
      return;
    }
    const nextQuery = { ...requestedQuery };
    const nextHistory = [...cursorHistory];
    setState(pageRef.current === null ? 'loading' : 'refreshing');

    const generation = generationRef.current + 1;
    generationRef.current = generation;
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;

    try {
      const nextPage = await client.getJson(
        buildAuditEventsUrl(nextQuery, cursor),
        parseAuditEventPage,
        controller.signal,
      );
      if (!mounted.current || generation !== generationRef.current) {
        return;
      }
      pageRef.current = nextPage;
      queryRef.current = nextQuery;
      cursorRef.current = cursor;
      cursorHistoryRef.current = nextHistory;
      setPage(nextPage);
      setQuery(nextQuery);
      setCanGoBack(nextHistory.length > 0);
      setState('ready');
    } catch (error) {
      if (!mounted.current || generation !== generationRef.current) {
        return;
      }
      setState(pageRef.current === null ? 'unavailable' : 'stale');
      throw error;
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
      }
    }
  }, [client]);

  useEffect(() => {
    mounted.current = true;
    const query = defaultQuery();
    void loadPage(query, undefined, []).catch(() => undefined);

    return () => {
      mounted.current = false;
      generationRef.current += 1;
      activeRequest.current?.abort();
      activeRequest.current = null;
    };
  }, [loadPage]);

  const applyQuery = useCallback(async (nextQuery: AuditListQuery) => {
    await loadPage(nextQuery, undefined, []);
  }, [loadPage]);

  const refresh = useCallback(async () => {
    if (activeRequest.current !== null) {
      return;
    }
    await loadPage(
      queryRef.current,
      cursorRef.current,
      cursorHistoryRef.current,
    );
  }, [loadPage]);

  const nextPage = useCallback(async () => {
    if (activeRequest.current !== null) {
      return;
    }
    const nextCursor = pageRef.current?.next_cursor;
    if (nextCursor === null || nextCursor === undefined) {
      return;
    }
    await loadPage(
      queryRef.current,
      nextCursor,
      [...cursorHistoryRef.current, cursorRef.current],
    );
  }, [loadPage]);

  const previousPage = useCallback(async () => {
    if (activeRequest.current !== null) {
      return;
    }
    const history = cursorHistoryRef.current;
    if (history.length === 0) {
      return;
    }
    await loadPage(
      queryRef.current,
      history[history.length - 1],
      history.slice(0, -1),
    );
  }, [loadPage]);

  return {
    state,
    page,
    query,
    canGoBack,
    applyQuery,
    refresh,
    nextPage,
    previousPage,
  };
}
