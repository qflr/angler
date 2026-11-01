// Honeypot build jobs: the CVE-in -> research -> build -> contain -> publish pipeline.
// Talks to the backend when VITE_API_URL is set, otherwise runs a timed simulation.
// Also falls back to the simulation if the backend doesn't serve /api/honeypots yet (404/405, or
// a CORS block), so the CVE-in flow keeps working against a backend with only the dashboard endpoints.

import { usingMock } from './api';
import { addDemoHoneypot, mockCves } from './mock';
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

type Advisory = NonNullable<HoneypotJob['advisory']>;
const mockJobs = new Map<string, { job: HoneypotJob; started: number; advisory?: Advisory }>();

// Demo traffic is simulated, but the advisory is real: the public cvelistV5 record (CORS-open).
async function realAdvisory(cveId: string): Promise<Advisory | null> {
  const [, year, num] = cveId.split('-');
  const url = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${Math.floor(Number(num) / 1000)}xxx/${cveId}.json`;
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    const rec = await res.json();
    const cna = rec.containers?.cna ?? {};
    const adp: { metrics?: Record<string, { baseScore?: number }>[] }[] = rec.containers?.adp ?? [];
    const affected = (cna.affected ?? []).find((a: { product?: string }) => a.product && a.product.toLowerCase() !== 'n/a');
    const vendor = affected?.vendor && affected.vendor.toLowerCase() !== 'n/a' ? affected.vendor : '';
    const product = affected ? (affected.product.toLowerCase().startsWith(vendor.toLowerCase()) ? affected.product : `${vendor} ${affected.product}`.trim()) : null;
    const desc: string = cna.title || (cna.descriptions ?? []).find((d: { lang?: string }) => d.lang?.startsWith('en'))?.value || '';
    let cvss: number | null = null;
    for (const m of [...(cna.metrics ?? []), ...adp.flatMap((a) => a.metrics ?? [])]) {
      for (const key of ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']) {
        const score = (m as Record<string, { baseScore?: number }>)[key]?.baseScore;
        if (cvss == null && typeof score === 'number') cvss = score;
      }
    }
    return { description: desc.split(/(?<=[.!?])\s+/)[0].slice(0, 240), product, cvss, kev: false };
  } catch {
    return null;
  }
}

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
      status === 'researching'
        ? null
        : known
          ? { description: known.description, product: known.product, cvss: known.cvss, kev: known.kev }
          : entry.advisory ?? demoAdvisory(job.cve_id),
  };
}

// Fallback only, for IDs cvelistV5 doesn't have (made-up or reserved): a plausible advisory, stable per ID.
const DEMO_PRODUCTS = [
  ['Ivanti Connect Secure', 'authentication bypass leading to remote command execution'],
  ['Fortinet FortiOS SSL-VPN', 'heap overflow allowing unauthenticated code execution'],
  ['Citrix NetScaler ADC', 'unauthenticated remote code execution in the gateway'],
  ['Atlassian Confluence Data Center', 'template injection allowing remote code execution'],
  ['Cisco IOS XE Web UI', 'privilege escalation via the web management interface'],
  ['GitLab CE/EE', 'arbitrary file write via project import'],
  ['Apache ActiveMQ', 'deserialization leading to remote code execution'],
  ['Jenkins', 'arbitrary file read through the CLI parser'],
] as const;

function demoAdvisory(cveId: string) {
  let h = 0;
  for (const ch of cveId) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  const [product, flaw] = DEMO_PRODUCTS[h % DEMO_PRODUCTS.length];
  const description = flaw[0].toUpperCase() + flaw.slice(1);
  return { description, product, cvss: Math.round((8.1 + ((h >>> 4) % 19) / 10) * 10) / 10, kev: h % 3 === 0 };
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
  const entry: { job: HoneypotJob; started: number; advisory?: Advisory } = {
    job: { id, cve_id: cveId, status: 'researching' },
    started: Date.now(),
  };
  mockJobs.set(id, entry);
  // Research runs for a few seconds in the simulation; the real record arrives well within that.
  realAdvisory(cveId).then((a) => {
    if (a) entry.advisory = a;
  });
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
  addDemoHoneypot(entry.job);
  return { ...entry.job };
}
