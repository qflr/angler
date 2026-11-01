"""Attacker dossiers: collapse many source IPs into one actor, and tag where traffic comes from.

Clustering (union-find over recent hits). Two IPs are the same actor when they share:
  - a known research-scanner identity (SANS ISC list: Censys, Shodan, Expanse, ...)
  - a payload fingerprint: the same exploit body/path with IPs, hosts and numbers blanked out
    (botnets reuse one template and only swap the download server)
  - a malware download URL host inside the payload (the strongest link)
  - the same /24 network and the same User-Agent
Tags per actor: scanner (SANS research list or a self-identifying UA), tor (Tor exit list),
cloud (hosting network per ip-api), vpn (proxy/VPN per ip-api), residential (none of those).
Timezone is guessed from activity rhythm only once an actor has hits spread over 6+ hours.

All inputs are observed data; no model involved.
"""

import hashlib
import re
import threading
import time
from collections import Counter, defaultdict

import httpx

from . import db

RESEARCH_URL = "https://isc.sans.edu/api/threatcategory/research?json"
TOR_URL = "https://check.torproject.org/torbulkexitlist"
LIST_TTL = 6 * 3600
WINDOW_HOURS = 7 * 24
SCANNER_UA = re.compile(r"censys|shodan|zgrab|masscan|nmap|expanse|internet-?measurement|onyphe|"
                        r"netcraft|leakix|binaryedge|research|scanner|bot\b", re.I)
_URL_HOST = re.compile(r"(?:https?|tftp|ftp)://([a-z0-9.\-]+)", re.I)
_NOISE_TOKENS = re.compile(r"\d+(\.\d+){3}(:\d+)?|https?://[^\s'\"`;)]+|[0-9a-f]{8,}|\d+", re.I)

_lists = {"research": {}, "tor": set(), "loaded_at": 0.0}
_lists_lock = threading.Lock()
_cache: dict = {"key": None, "value": None}


# --- reference lists ------------------------------------------------------------------------------

def _load_lists() -> None:
    research, tor = {}, set()
    try:
        res = httpx.get(RESEARCH_URL, timeout=60, headers={"User-Agent": "angler (LarpHacks 2026)"})
        research = {r["ipv4"]: r["type"] for r in res.json() if r.get("ipv4")}
    except (httpx.HTTPError, ValueError, KeyError):
        pass
    try:
        res = httpx.get(TOR_URL, timeout=30)
        tor = {line.strip() for line in res.text.splitlines() if line.strip() and not line.startswith("#")}
    except httpx.HTTPError:
        pass
    with _lists_lock:
        if research:
            _lists["research"] = research
        if tor:
            _lists["tor"] = tor
        _lists["loaded_at"] = time.time()


def refresh_lists_in_background() -> None:
    def loop():
        while True:
            _load_lists()
            time.sleep(LIST_TTL)

    threading.Thread(target=loop, daemon=True).start()


# --- clustering -----------------------------------------------------------------------------------

def fingerprint(path: str, body: str) -> str | None:
    """Exploit template with the variable parts blanked; None for trivial requests."""
    text = f"{path}\n{body}".strip()
    if len(text) < 12 or path in ("/", "/favicon.ico", "/robots.txt"):
        return None
    return hashlib.sha1(_NOISE_TOKENS.sub("#", text).encode()).hexdigest()[:16]


class _UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _timezone(timestamps: list[str]) -> str | None:
    """Peak activity hour -> UTC offset, assuming bots run hardest around local 02:00-04:00."""
    hours = [int(t[11:13]) for t in timestamps]
    if len(set(hours)) < 6:
        return None
    peak = Counter(hours).most_common(1)[0][0]
    offset = (3 - peak + 12) % 24 - 12
    return f"UTC{offset:+03d}"


def build(rows: list[dict]) -> tuple[dict[str, str], list[dict]]:
    """rows: recent non-test events. Returns ({ip: actor_id}, [actor dossiers])."""
    research = _lists["research"]
    tor = _lists["tor"]
    uf = _UnionFind()
    by_key: dict[str, str] = {}

    def link(key: str, ip: str) -> None:
        if key in by_key:
            uf.union(by_key[key], ip)
        else:
            by_key[key] = ip

    for r in rows:
        ip = r["source_ip"]
        uf.find(ip)
        if ip in research:
            link(f"scanner:{research[ip]}", ip)
        fp = fingerprint(r["path"] or "", r["body_preview"] or "")
        # Only real payload templates link IPs; a bare probe path is identical for every scanner.
        if fp and r["cve_id"] and (r["body_preview"] or "").strip():
            link(f"fp:{fp}", ip)
        for host in _URL_HOST.findall(f"{r['path']} {r['body_preview']}"):
            link(f"dl:{host.lower()}", ip)
        if r["user_agent"] and "." in ip:
            link(f"net:{ip.rsplit('.', 1)[0]}|ua:{r['user_agent']}", ip)

    members: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        members[uf.find(r["source_ip"])].append(r)

    ip_to_actor, actors = {}, []
    for root, hits in members.items():
        ips = sorted({h["source_ip"] for h in hits})
        actor_id = "act_" + hashlib.sha1(root.encode()).hexdigest()[:6]
        for ip in ips:
            ip_to_actor[ip] = actor_id

        scanner_names = sorted({research[ip] for ip in ips if ip in research})
        uas = [h["user_agent"] or "" for h in hits]
        tags = set()
        if scanner_names or any(SCANNER_UA.search(ua) for ua in uas):
            tags.add("scanner")
        if any(ip in tor for ip in ips):
            tags.add("tor")
        if any(h["hosting"] for h in hits):
            tags.add("cloud")
        if any(h["proxy"] for h in hits):
            tags.add("vpn")
        if not tags & {"scanner", "tor", "cloud", "vpn"} and any(h["hosting"] == 0 for h in hits):
            tags.add("residential")

        times = sorted(h["timestamp"] for h in hits)
        label = scanner_names[0].capitalize() if len(scanner_names) == 1 else f"AX-{actor_id[4:7].upper()}"
        actors.append(
            {
                "id": actor_id,
                "label": label,
                "ips": ips,
                "asns": sorted({h["asn"] for h in hits if h["asn"]}),
                "classification": "targeted" if any(h["classification"] == "targeted" for h in hits) else "noise",
                "hit_count": len(hits),
                "first_seen": times[0],
                "last_seen": times[-1],
                "countries": sorted({h["country_code"] for h in hits if h["country_code"]}) or None,
                "tags": sorted(tags) or None,
                "timezone": _timezone(times),
                "cves": sorted({h["cve_id"] for h in hits if h["cve_id"]}) or None,
            }
        )
    # Targeted actors first, most recently active first within each group.
    actors.sort(key=lambda a: a["last_seen"], reverse=True)
    actors.sort(key=lambda a: a["classification"] != "targeted")
    return ip_to_actor, actors


def current() -> tuple[dict[str, str], list[dict]]:
    """Clusters over the last week of real hits, recomputed only when new hits arrive."""
    conn = db.connect()
    try:
        since = db.hours_ago(WINDOW_HOURS)
        stamp = conn.execute(
            "SELECT COUNT(*) AS n, MAX(timestamp) AS t FROM events WHERE is_test = 0 AND timestamp >= ?", (since,)
        ).fetchone()
        key = (db.DATABASE_URL or str(db.DB_PATH), stamp["n"], stamp["t"], _lists["loaded_at"])
        if _cache["key"] == key:
            return _cache["value"]
        rows = conn.execute(
            """SELECT e.source_ip, e.asn, e.country_code, e.classification, e.cve_id, e.timestamp, e.path,
                      e.body_preview, e.user_agent, i.hosting, i.proxy
               FROM events e LEFT JOIN ip_info i ON i.ip = e.source_ip
               WHERE e.is_test = 0 AND e.timestamp >= ?""",
            (since,),
        ).fetchall()
    finally:
        conn.close()
    value = build([dict(r) for r in rows])
    _cache.update(key=key, value=value)
    return value
