"""Source attribution for attacker IPs: country, city, coordinates, ASN and network owner.

Uses ip-api.com's free batch endpoint (100 IPs per call, no key; non-commercial use, 15 calls/min).
Results are cached in the ip_info table, so each attacker IP is looked up once.
"""

import ipaddress

import httpx

from . import db

BATCH_URL = "http://ip-api.com/batch?fields=status,query,country,countryCode,regionName,city,lat,lon,as,org,isp,hosting,proxy"


def _asn(as_field: str | None) -> int | None:
    # "AS14061 DigitalOcean, LLC" -> 14061
    if as_field and as_field.startswith("AS"):
        num = as_field[2:].split(" ", 1)[0]
        return int(num) if num.isdigit() else None
    return None


def lookup(conn: db.Conn, ips: list[str]) -> dict[str, dict]:
    """Geo/ASN for each IP (cached). Private or unresolvable addresses come back as {}."""
    ips = sorted(set(ips))
    found: dict[str, dict] = {}
    marks = ",".join("?" * len(ips)) or "''"
    for r in conn.execute(f"SELECT * FROM ip_info WHERE ip IN ({marks})", ips):
        found[r["ip"]] = dict(r)

    todo = []
    for ip in ips:
        if ip in found:
            continue
        try:
            if not ipaddress.ip_address(ip).is_global:
                found[ip] = {}
                continue
        except ValueError:
            found[ip] = {}
            continue
        todo.append(ip)

    for i in range(0, len(todo), 100):
        try:
            res = httpx.post(BATCH_URL, json=todo[i : i + 100], timeout=10)
            res.raise_for_status()
            results = res.json()
        except (httpx.HTTPError, ValueError):
            break  # leave the rest unresolved; the next ingest retries them
        with conn:
            for r in results:
                if r.get("status") != "success":
                    continue
                info = {
                    "ip": r["query"],
                    "asn": _asn(r.get("as")),
                    "org": r.get("org") or r.get("isp"),
                    "country": r.get("country"),
                    "country_code": r.get("countryCode"),
                    "region": r.get("regionName"),
                    "city": r.get("city"),
                    "lat": r.get("lat"),
                    "lng": r.get("lon"),
                    "hosting": 1 if r.get("hosting") else 0,
                    "proxy": 1 if r.get("proxy") else 0,
                    "looked_up_at": db.now_iso(),
                }
                conn.execute(
                    """INSERT INTO ip_info (ip, asn, org, country, country_code, region, city, lat, lng, hosting,
                           proxy, looked_up_at)
                       VALUES (:ip, :asn, :org, :country, :country_code, :region, :city, :lat, :lng, :hosting,
                           :proxy, :looked_up_at)
                       ON CONFLICT (ip) DO NOTHING""",
                    info,
                )
                found[info["ip"]] = info
    return found
