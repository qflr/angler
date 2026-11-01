// JSON contract between the dashboard and the FastAPI backend.
// Human-readable spec with examples: docs/api-contract.md. Keep both in sync.

export type Classification = 'noise' | 'targeted';

/** How far along the kill chain a request got. */
export type Stage = 'recon' | 'probe' | 'exploit';

export type SourceTag = 'tor' | 'vpn' | 'cloud' | 'residential' | 'scanner';

/** GET /api/cves -> Cve[] */
export interface Cve {
  id: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  status: 'urgent' | 'high' | 'watch';
  kev: boolean;
  patch_status: 'patched' | 'partial' | 'unpatched' | 'unknown';
  cvss?: number | null;
  product?: string | null;
  published?: string | null;
}

/** GET /api/events -> AttackEvent[] (newest first) */
export interface AttackEvent {
  id: string;
  source_ip: string;
  asn: number;
  port: number;
  timestamp: string;
  classification: Classification;
  org?: string | null;
  country?: string | null;
  country_code?: string | null;
  region?: string | null;
  city?: string | null;
  lat?: number | null;
  lng?: number | null;
  cve_id?: string | null;
  method?: string | null;
  path?: string | null;
  stage?: Stage | null;
  actor_id?: string | null;
}

/** GET /api/stats -> Stats */
export interface Stats {
  new_cves: number;
  updated_cves: number;
  newly_patched: number;
  newly_kev: number;
  total_hits: number;
  window?: string | null;
}

/** GET /api/actors -> Actor[] */
export interface Actor {
  id: string;
  label: string;
  ips: string[];
  asns: number[];
  classification: Classification;
  hit_count: number;
  first_seen: string;
  last_seen: string;
  countries?: string[] | null;
  tags?: SourceTag[] | null;
  timezone?: string | null;
  cves?: string[] | null;
}

/** Pipeline stage of a honeypot build: research -> build -> contain -> ready -> published. */
export type HoneypotStatus = 'researching' | 'building' | 'containing' | 'ready' | 'published' | 'failed';

/** POST /api/honeypots, GET /api/honeypots/{id}, POST /api/honeypots/{id}/publish -> HoneypotJob */
export interface HoneypotJob {
  id: string;
  cve_id: string;
  status: HoneypotStatus;
  /** Filled in once research finds an advisory. */
  advisory?: Pick<Cve, 'description' | 'product' | 'cvss' | 'kev'> | null;
  /** Public URL of the decoy; set when published. */
  url?: string | null;
  error?: string | null;
}

export interface LiveData {
  cves: Cve[];
  events: AttackEvent[];
  stats: Stats;
  actors: Actor[];
  /** Published honeypots (GET /api/honeypots); the dashboard shows one tab per CVE. */
  honeypots: HoneypotJob[];
}
