import { useEffect, useState } from 'react';
import { fetchAll } from './api';
import type { LiveData } from './types';

const POLL_MS = 3000;

export function useLive() {
  const [data, setData] = useState<LiveData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const next = await fetchAll();
        if (!alive) return;
        setData(next);
        setError(null);
        setUpdatedAt(Date.now());
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    };
    tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return { data, error, updatedAt };
}
