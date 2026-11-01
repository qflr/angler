// Honeypot build jobs: the CVE-in -> research -> build -> contain -> publish pipeline.
// Talks to the backend when VITE_API_URL is set, otherwise runs a timed simulation.
// Also falls back to the simulation if the backend doesn't serve /api/honeypots yet (404/405, or
// a CORS block), so the CVE-in flow keeps working against a backend with only the dashboard endpoints.

import { usingMock } from './api';
import { mockCves } from './mock';
import type { HoneypotJob, HoneypotStatus } from './types';

const API_URL = (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, '');

export const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;

async function send<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw Object.assign(new Error(`${method} ${path} failed: ${res.status}`), { status: res.status });
  return res.json();
}

// 404/405: route not built yet. TypeError: the browser blocked the request, which is what a
// GET-only CORS policy does to this POST's preflight.
const notServed = (e: unknown) => e instanceof TypeError || [404, 405].includes((e as { status?: number }).status ?? 0);
// Simulated jobs are tracked locally even when a backend is configured.
const isSimulated = (id: string) => mockJobs.has(id);

// --- simulation ---------------------------------------------------------------

// Cumulative ms at which each stage finishes.
const STAGE_END: [HoneypotStatus, number][] = [
  ['researching', 3500],
  ['building', 7500],
  ['containing', 10500],
];

const mockJobs = new Map<string, { job: HoneypotJob; started: number }>();

function mockStatus(started: number): HoneypotStatus {
  const elapsed = Date.now() - started;
  return STAGE_END.find(([, end]) => elapsed < end)?.[0] ?? 'ready';
}

function mockView(id: string): HoneypotJob {
  const entry = mockJobs.get(id);
  if (!entry) throw new Error(`Unknown job ${id}`);
  const { job, started } = entry;
  if (job.status === 'published') return { ...job };
  const status = mockStatus(started);
  const known = mockCves().find((c) => c.id === job.cve_id);
  return {
    ...job,
    status,
    advisory:
      status === 'researching' || !known
        ? null
        : { description: known.description, product: known.product, cvss: known.cvss, kev: known.kev },
  };
}

// --- API ----------------------------------------------------------------------

export async function createHoneypot(cveId: string): Promise<HoneypotJob> {
  if (!usingMock) {
    try {
      return await send('POST', '/api/honeypots', { cve_id: cveId });
    } catch (e) {
      if (!notServed(e)) throw e;
    }
  }
  const id = `hp_sim_${Date.now().toString(36)}`;
  mockJobs.set(id, { job: { id, cve_id: cveId, status: 'researching' }, started: Date.now() });
  return mockView(id);
}

export async function getHoneypot(id: string): Promise<HoneypotJob> {
  if (!isSimulated(id)) return send('GET', `/api/honeypots/${id}`);
  return mockView(id);
}

export async function publishHoneypot(id: string): Promise<HoneypotJob> {
  if (!isSimulated(id)) return send('POST', `/api/honeypots/${id}/publish`);
  const entry = mockJobs.get(id)!;
  entry.job = { ...mockView(id), status: 'published', url: `/decoy.html?cve=${encodeURIComponent(entry.job.cve_id)}` };
  return { ...entry.job };
}
