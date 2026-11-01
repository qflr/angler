// Client-side rollups of GET /api/events for the charts. The contract only ships raw
// events, so anything time-bucketed or grouped is computed here.

import type { AttackEvent, Stage } from './types';

const MIN = 60_000;
const at = (e: AttackEvent) => Date.parse(e.timestamp);

export interface SeriesPoint {
  t: number;
  noise: number;
  targeted: number;
}

/** One bucket per complete minute for the last `minutes` minutes. */
export function minuteSeries(events: AttackEvent[], now: number, minutes = 30): SeriesPoint[] {
  const end = Math.floor(now / MIN) * MIN;
  const start = end - minutes * MIN;
  const pts = Array.from({ length: minutes }, (_, i) => ({ t: start + i * MIN, noise: 0, targeted: 0 }));
  for (const e of events) {
    const i = Math.floor((at(e) - start) / MIN);
    if (i >= 0 && i < minutes) pts[i][e.classification]++;
  }
  return pts;
}

export function activeSources(events: AttackEvent[], now: number, windowMs = 5 * MIN) {
  return new Set(events.filter((e) => at(e) >= now - windowMs).map((e) => e.source_ip)).size;
}

export function stageBreakdown(events: AttackEvent[], now: number, windowMs = 30 * MIN) {
  const counts: Record<Stage, number> = { recon: 0, probe: 0, exploit: 0 };
  const paths: Record<Stage, Map<string, number>> = { recon: new Map(), probe: new Map(), exploit: new Map() };
  let any = false;
  for (const e of events) {
    if (!e.stage || at(e) < now - windowMs) continue;
    any = true;
    counts[e.stage]++;
    if (e.path) paths[e.stage].set(e.path, (paths[e.stage].get(e.path) ?? 0) + 1);
  }
  const top = (m: Map<string, number>) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([p]) => p);
  return { any, counts, topPaths: { recon: top(paths.recon), probe: top(paths.probe), exploit: top(paths.exploit) } };
}

export function topLocations(events: AttackEvent[], n = 5) {
  const m = new Map<string, number>();
  for (const e of events) {
    if (!e.country) continue;
    const label = [e.country, e.region, e.city].filter(Boolean).join(' · ');
    m.set(label, (m.get(label) ?? 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([label, count]) => ({ label, count }));
}

export function hitsByCve(events: AttackEvent[]) {
  const m = new Map<string, { hits: number; targeted: number }>();
  for (const e of events) {
    if (!e.cve_id) continue;
    const r = m.get(e.cve_id) ?? { hits: 0, targeted: 0 };
    r.hits++;
    if (e.classification === 'targeted') r.targeted++;
    m.set(e.cve_id, r);
  }
  return m;
}
