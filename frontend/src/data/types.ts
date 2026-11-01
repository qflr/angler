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
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'urgent' | 'high' | 'watch';
  kev: boolean;
  patch_status: 'patched' | 'partial' | 'unpatched';
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

export interface LiveData {
  cves: Cve[];
  events: AttackEvent[];
  stats: Stats;
  actors: Actor[];
}
