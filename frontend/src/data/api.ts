import { mockActors, mockCves, mockEvents, mockHoneypots, mockStats } from './mock';
import { MODE } from './mode';
import type { Actor, AttackEvent, Cve, HoneypotJob, LiveData, Stats } from './types';

const API_URL = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '');

/** True when no backend is configured and the dashboard runs on simulated traffic. */
export const usingMock = !API_URL || MODE === 'demo';

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

/** GET /api/actors/{id}: one dossier plus every request that actor sent. */
export interface ActorDetailData extends Actor {
  user_agents: string[];
  download_urls: string[];
  paths: { path: string; count: number }[];
  hits: (AttackEvent & { body_preview?: string | null; user_agent?: string | null })[];
}

export const fetchActorDetail = (id: string) => get<ActorDetailData>(`/api/actors/${encodeURIComponent(id)}`);

// Tabs are optional: an older backend without /api/honeypots just shows "All traffic".
export const fetchHoneypots = () =>
  usingMock ? Promise.resolve(mockHoneypots()) : get<HoneypotJob[]>('/api/honeypots').catch(() => [] as HoneypotJob[]);

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
