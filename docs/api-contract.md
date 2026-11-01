# Angler API contract

The FastAPI backend serves these four endpoints. The frontend polls all four every 3 seconds.
Until the backend is live, the frontend serves the same shapes from `frontend/src/data/mock.ts`.
The TypeScript source of truth is `frontend/src/data/types.ts`. Keep the two in sync.

- JSON field names are `snake_case`.
- Timestamps are ISO 8601 UTC strings, e.g. `"2026-11-01T17:42:05Z"`.
- Enable CORS for the frontend's origin (the Render static-site URL and `http://localhost:5173`).
- Fields marked *optional* can be omitted or `null`. Required fields must always be present.

---

## Changelog

- **Nov 1, Phase 3 (backend live on real data):** `severity` and `patch_status` gained an `"unknown"`
  value. The backend never guesses a band or claims "unpatched" without a source. **Frontend: add
  `| 'unknown'` to both unions in `frontend/src/data/types.ts`.** The current Badge maps already render
  it as a neutral "Unknown" badge. `/api/cves` also accepts `?limit=` (default 500, urgent first).
  `/api/events` and `/api/actors` are empty until the honeypot is live; `/api/stats` counts are real.
- Live API: `https://angler-api.onrender.com` (pipeline health at `/status`).

## `GET /api/cves`

CVE records the system is tracking or impersonating. Returns a JSON array.

| field | type | notes |
|---|---|---|
| `id` | string | `"CVE-2024-3400"` |
| `description` | string | One-line summary |
| `severity` | `"critical" \| "high" \| "medium" \| "low" \| "unknown"` | CVSS severity band. `unknown` = no CVSS score published yet (common for CVEs under a day old) |
| `status` | `"urgent" \| "high" \| "watch"` | Our triage priority: `urgent` = in CISA KEV; `high` = no complete fix + code execution + remotely reachable + CVSS ≥ 7; else `watch` |
| `kev` | boolean | Listed in CISA Known Exploited Vulnerabilities |
| `patch_status` | `"patched" \| "partial" \| "unpatched" \| "unknown"` | Whether a vendor fix exists. `unknown` = no source (OSV, GitHub Advisories, the CVE record) says either way |
| `cvss` | number | *optional.* Base score, e.g. `10.0` |
| `product` | string | *optional.* `"Palo Alto PAN-OS"` |
| `published` | string | *optional.* ISO timestamp |

```json
[
  {
    "id": "CVE-2024-3400",
    "description": "GlobalProtect OS command injection",
    "severity": "critical",
    "status": "urgent",
    "kev": true,
    "patch_status": "patched",
    "cvss": 10.0,
    "product": "Palo Alto PAN-OS",
    "published": "2024-04-12T00:00:00Z"
  }
]
```

## `GET /api/events?limit=1000`

Recent attack hits, **newest first**. `limit` defaults to 1000. The frontend builds the
noise-vs-targeted chart from the last 30 minutes of events, so return at least that much history.

| field | type | notes |
|---|---|---|
| `id` | string | Unique per hit |
| `source_ip` | string | |
| `asn` | number | `14061` |
| `port` | number | Destination port on the honeypot |
| `timestamp` | string | ISO timestamp |
| `classification` | `"noise" \| "targeted"` | `targeted` = carries a probe/exploit for one of our CVEs |
| `org` | string | *optional.* ASN owner, `"DigitalOcean"` |
| `country` | string | *optional.* `"Canada"` |
| `country_code` | string | *optional.* ISO 3166-1 alpha-2, `"CA"` |
| `region` | string | *optional.* `"Ontario"` |
| `city` | string | *optional.* `"Toronto"` |
| `lat`, `lng` | number | *optional.* **Required for the globe** |
| `cve_id` | string | *optional.* CVE the request targets |
| `method`, `path` | string | *optional.* HTTP request line |
| `stage` | `"recon" \| "probe" \| "exploit"` | *optional.* Drives the Attack behavior card |
| `actor_id` | string | *optional.* Links to `/api/actors` |

The optional geo fields aren't in the minimal contract, but the globe and the Hits by location card
stay empty without them. Please include them if the GeoIP lookup is available.

```json
[
  {
    "id": "h_1a2b",
    "source_ip": "185.220.101.60",
    "asn": 60729,
    "port": 443,
    "timestamp": "2026-11-01T17:42:05Z",
    "classification": "targeted",
    "org": "Tor exit relay",
    "country": "Germany",
    "country_code": "DE",
    "region": "Berlin",
    "city": "Berlin",
    "lat": 52.52,
    "lng": 13.4,
    "cve_id": "CVE-2024-23897",
    "method": "POST",
    "path": "/cli?remoting=false",
    "stage": "exploit",
    "actor_id": "act_a11"
  }
]
```

## `GET /api/stats`

Counts for the top metric cards. Counts cover the last 24 hours unless `window` says otherwise.

| field | type | notes |
|---|---|---|
| `new_cves` | number | CVEs first published in the window |
| `updated_cves` | number | Existing CVEs whose record changed |
| `newly_patched` | number | CVEs whose `patch_status` became `patched` |
| `newly_kev` | number | CVEs newly added to CISA KEV |
| `total_hits` | number | Honeypot hits in the window |
| `window` | string | *optional.* Label, default `"24h"` |

```json
{ "new_cves": 287, "updated_cves": 1043, "newly_patched": 61, "newly_kev": 3, "total_hits": 18422, "window": "24h" }
```

## `GET /api/actors`

Attacker dossiers: multiple IPs collapsed into one actor using shared fingerprints.

| field | type | notes |
|---|---|---|
| `id` | string | `"act_a11"` |
| `label` | string | Cluster code (`"AX-A11"`) or known name (`"Censys"`) |
| `ips` | string[] | Member IPs |
| `asns` | number[] | |
| `classification` | `"noise" \| "targeted"` | `targeted` if any hit was targeted |
| `hit_count` | number | |
| `first_seen`, `last_seen` | string | ISO timestamps |
| `countries` | string[] | *optional.* Country codes |
| `tags` | (`"tor" \| "vpn" \| "cloud" \| "residential" \| "scanner"`)[] | *optional* |
| `timezone` | string | *optional.* Inferred from activity rhythm, `"UTC+08"` |
| `cves` | string[] | *optional.* CVEs this actor targeted |

```json
[
  {
    "id": "act_a11",
    "label": "AX-A11",
    "ips": ["185.220.101.60", "109.70.100.12"],
    "asns": [60729, 208323],
    "classification": "targeted",
    "hit_count": 46,
    "first_seen": "2026-11-01T16:10:00Z",
    "last_seen": "2026-11-01T17:42:05Z",
    "countries": ["DE", "NL"],
    "tags": ["tor"],
    "timezone": "unknown",
    "cves": ["CVE-2024-4577", "CVE-2024-23897"]
  }
]
```

---

## Proposed: honeypot build pipeline

*Added by the frontend for the CVE-in flow; not built on the backend yet. The frontend simulates
these until they exist (`frontend/src/data/honeypot.ts`). Push back on shape or naming here before
implementing.*

The flow: user pastes a CVE → **research** (verified advisories, PoCs) → **build** (generate the
vulnerable app) → **contain** (isolated, hollow, no egress, disposable) → **ready** → user clicks
publish → **published** (decoy is live; exploit verification and attacker tracking begin, and the
dashboard endpoints above start reporting its traffic).

All three endpoints return a `HoneypotJob`:

| field | type | notes |
|---|---|---|
| `id` | string | `"hp_8f3k2"` |
| `cve_id` | string | |
| `status` | `"researching" \| "building" \| "containing" \| "ready" \| "published" \| "failed"` | |
| `advisory` | object | *optional.* `{ description, product, cvss, kev }` once research finds it |
| `url` | string | *optional.* Public decoy URL, set when `published` |
| `error` | string | *optional.* Reason when `failed` |

### `POST /api/honeypots`

Body `{ "cve_id": "CVE-2024-3400" }`. Starts the pipeline and returns the job (status `researching`).

### `GET /api/honeypots/{id}`

Current job state. The frontend polls this every 800 ms until `ready`, `published` or `failed`.

### `POST /api/honeypots/{id}/publish`

Only valid when `status` is `ready`. Exposes the contained decoy and returns the job with
`status: "published"` and `url` set. The frontend opens `url` in a new tab.

```json
{
  "id": "hp_8f3k2",
  "cve_id": "CVE-2024-3400",
  "status": "published",
  "advisory": { "description": "GlobalProtect OS command injection", "product": "Palo Alto PAN-OS", "cvss": 10.0, "kev": true },
  "url": "https://decoy-8f3k2.onrender.com/"
}
```
