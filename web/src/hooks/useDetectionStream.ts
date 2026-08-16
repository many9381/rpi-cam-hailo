import { useEffect, useRef, useState } from 'react';

import { parseDetectionSnapshot } from '../api/contracts';
import type { DetectionSnapshot } from '../api/types';

const reconnectingGraceMs = 3000;

export type DetectionStreamStatus =
  | 'connecting'
  | 'live'
  | 'reconnecting'
  | 'closed';

export interface DetectionStreamState {
  status: DetectionStreamStatus;
  snapshot: DetectionSnapshot;
}

export function useDetectionStream(
  initialSnapshot: DetectionSnapshot,
  active = true,
): DetectionStreamState {
  const initialSnapshotRef = useRef(initialSnapshot);
  initialSnapshotRef.current = initialSnapshot;
  const [state, setState] = useState<DetectionStreamState>({
    status: active ? 'connecting' : 'closed',
    snapshot: initialSnapshot,
  });

  useEffect(() => {
    if (!active) {
      setState((current) => ({ ...current, status: 'closed' }));
      return;
    }
    if (typeof EventSource === 'undefined') {
      setState((current) => ({ ...current, status: 'closed' }));
      return;
    }

    let current = true;
    let lastEventAt = Date.now();
    let graceTimer: number | undefined;
    const clearGraceTimer = () => {
      if (graceTimer !== undefined) {
        window.clearTimeout(graceTimer);
        graceTimer = undefined;
      }
    };
    setState({ status: 'connecting', snapshot: initialSnapshotRef.current });
    const source = new EventSource('/api/v1/ai/detections/stream');
    source.onerror = () => {
      if (!current) {
        return;
      }
      // The server finishes the response after every long-poll event, so the
      // browser sees a routine close here; only a sustained event gap means
      // the stream is actually unhealthy.
      const idleMs = Date.now() - lastEventAt;
      if (idleMs >= reconnectingGraceMs) {
        setState((value) => ({ ...value, status: 'reconnecting' }));
        return;
      }
      if (graceTimer === undefined) {
        graceTimer = window.setTimeout(() => {
          graceTimer = undefined;
          if (current) {
            setState((value) => ({ ...value, status: 'reconnecting' }));
          }
        }, reconnectingGraceMs - idleMs);
      }
    };
    source.addEventListener('detections', (event) => {
      if (!current || !(event instanceof MessageEvent)) {
        return;
      }
      try {
        const snapshot = parseDetectionSnapshot(JSON.parse(event.data));
        lastEventAt = Date.now();
        clearGraceTimer();
        setState({ status: 'live', snapshot });
      } catch {
        // Keep the last validated snapshot when an event is malformed.
      }
    });

    return () => {
      current = false;
      clearGraceTimer();
      source.close();
    };
  }, [active]);

  if (active && typeof EventSource !== 'undefined' && state.status === 'closed') {
    return { status: 'connecting', snapshot: initialSnapshot };
  }
  return state;
}
