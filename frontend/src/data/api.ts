import { mockActors, mockCves, mockEvents, mockStats } from './mock';
import type { Actor, AttackEvent, Cve, HoneypotJob, LiveData, Stats } from './types';

const API_URL = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '');

/** True when no backend is configured and the dashboard runs on simulated traffic. */
export const usingMock = !API_URL;

const EVENT_LIMIT = 1000;

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`);
  if (!res.ok) throw new Error(`GET ${path} failed: ${res.status}`);
  return res.json();
}

export const fetchCves = () => (usingMock ? Promise.resolve(mockCves()) : get<Cve[]>('/api/cves'));
export const fetchEvents = () =>
  usingMock ? Promise.resolve(mockEvents(EVENT_LIMIT)) : get<AttackEvent[]>(`/api/events?limit=${EVENT_LIMIT}`);
export const fetchStats = () => (usingMock ? Promise.resolve(mockStats()) : get<Stats>('/api/stats'));
export const fetchActors = () => (usingMock ? Promise.resolve(mockActors()) : get<Actor[]>('/api/actors'));

// Tabs are optional: an older backend without /api/honeypots just shows "All traffic".
export const fetchHoneypots = () =>
  usingMock ? Promise.resolve([] as HoneypotJob[]) : get<HoneypotJob[]>('/api/honeypots').catch(() => [] as HoneypotJob[]);

export async function fetchAll(): Promise<LiveData> {
  const [cves, events, stats, actors, honeypots] = await Promise.all([
    fetchCves(),
    fetchEvents(),
    fetchStats(),
    fetchActors(),
    fetchHoneypots(),
  ]);
  return { cves, events, stats, actors, honeypots };
}
