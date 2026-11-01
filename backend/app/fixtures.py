"""Phase 0 placeholder responses: the example records from docs/api-contract.md, verbatim.

These exist only so the frontend can integrate against a live URL before the pipeline lands.
They are served only when ANGLER_DATA_SOURCE=fixture, every response carries an
`X-Angler-Data-Source: fixture` header, and this module gets deleted in Phase 3.
No generated or randomized data: one static record per endpoint, nothing that looks like traffic.
"""

CVES = [
    {
        "id": "CVE-2024-3400",
        "description": "GlobalProtect OS command injection",
        "severity": "critical",
        "status": "urgent",
        "kev": True,
        "patch_status": "patched",
        "cvss": 10.0,
        "product": "Palo Alto PAN-OS",
        "published": "2024-04-12T00:00:00Z",
    }
]

EVENTS = [
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
        "actor_id": "act_a11",
    }
]

STATS = {
    "new_cves": 287,
    "updated_cves": 1043,
    "newly_patched": 61,
    "newly_kev": 3,
    "total_hits": 18422,
    "window": "24h",
}

ACTORS = [
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
        "cves": ["CVE-2024-4577", "CVE-2024-23897"],
    }
]
