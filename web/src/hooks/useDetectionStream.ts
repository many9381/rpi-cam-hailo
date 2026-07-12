import { useEffect, useRef, useState } from 'react';

import { parseDetectionSnapshot } from '../api/contracts';
import type { DetectionSnapshot } from '../api/types';

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
    setState({ status: 'connecting', snapshot: initialSnapshotRef.current });
    const source = new EventSource('/api/v1/ai/detections/stream');
    source.onopen = () => {
      if (current) {
        setState((value) => ({ ...value, status: 'live' }));
      }
    };
    source.onerror = () => {
      if (current) {
        setState((value) => ({ ...value, status: 'reconnecting' }));
      }
    };
    source.addEventListener('detections', (event) => {
      if (!current || !(event instanceof MessageEvent)) {
        return;
      }
      try {
        const snapshot = parseDetectionSnapshot(JSON.parse(event.data));
        setState((value) => ({ ...value, snapshot }));
      } catch {
        // Keep the last validated snapshot when an event is malformed.
      }
    });

    return () => {
      current = false;
      source.close();
    };
  }, [active]);

  if (active && typeof EventSource !== 'undefined' && state.status === 'closed') {
    return { status: 'connecting', snapshot: initialSnapshot };
  }
  return state;
}
