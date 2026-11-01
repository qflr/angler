"""Explain this traffic": condense what the dashboard shows into counts and ask Gemini to interpret them.

Only aggregates go to the model (top paths, countries, networks, user agents, stages, CVEs, actor tags),
never raw payload bodies. The prompt tells it to stay inside the numbers and to say when data is thin.
"""

import time
from collections import Counter

import httpx

from . import llm

MAX_EVENTS = 1000
_last_call = {"t": 0.0}
MIN_GAP_SECONDS = 5  # one Gemini call per 5 s across all viewers; it's a button, not a stream


class InsightError(Exception):
    pass


def _top(counter: Counter, n: int = 8) -> str:
    return ", ".join(f"{k} ({v})" for k, v in counter.most_common(n)) or "none"


def summarize(events: list[dict], actors: list[dict], scope: str) -> str:
    events = events[:MAX_EVENTS]
    c = lambda key: Counter(str(e.get(key)) for e in events if e.get(key))  # noqa: E731
    paths = Counter(f"{e.get('method', '')} {str(e.get('path', ''))[:80]}".strip() for e in events if e.get("path"))
    places = Counter(f"{e.get('city') or '?'}, {e.get('country') or '?'}" for e in events if e.get("country"))
    nets = Counter(f"AS{e.get('asn')} {e.get('org') or ''}".strip() for e in events if e.get("asn"))
    times = sorted(str(e["timestamp"]) for e in events if e.get("timestamp"))
    actor_lines = [
        f"- {a.get('label')}: {a.get('hit_count')} hits from {len(a.get('ips') or [])} IPs, "
        f"{a.get('classification')}, tags {a.get('tags') or []}, CVEs {a.get('cves') or []}"
        for a in actors[:8]
    ]
    return "\n".join(
        [
            f"Scope: {scope}",
            f"Requests: {len(events)} ({times[0] if times else '?'} to {times[-1] if times else '?'})",
            f"Classification: {_top(c('classification'))}",
            f"Stages: {_top(c('stage'))}",
            f"CVEs matched: {_top(c('cve_id'))}",
            f"Top requests: {_top(paths, 10)}",
            f"Ports: {_top(c('port'))}",
            f"Locations: {_top(places)}",
            f"Networks: {_top(nets)}",
            f"Distinct source IPs: {len({e.get('source_ip') for e in events})}",
            "Actors (clustered):",
            *(actor_lines or ["- none"]),
        ]
    )


def explain(events: list[dict], actors: list[dict], scope: str) -> dict:
    now = time.time()
    if now - _last_call["t"] < MIN_GAP_SECONDS:
        raise InsightError("Give it a few seconds between explanations.")
    _last_call["t"] = now

    facts = summarize(events, actors, scope)
    prompt = (
        "You are a threat-intelligence analyst looking at traffic captured by a honeypot (a decoy server that "
        "impersonates vulnerable software). Interpret the aggregated data below for a non-expert audience.\n"
        "Write 4 to 6 short bullet points, plain text, each starting with '- '. Cover: what most of this traffic "
        "probably is (e.g. search-engine crawlers, internet-wide research scanners like Censys/Shodan, botnets "
        "such as Mirai spraying router exploits, credential/secret scrapers), whether anything looks like "
        "deliberate exploitation of the impersonated CVE, and one thing worth watching. Tie each claim to the "
        "numbers. If the data is thin, say so. Do not invent IPs, names or facts that are not in the data.\n\n"
        f"{facts}"
    )
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 700, "thinkingConfig": {"thinkingBudget": 0}},
    }
    try:
        token = llm.access_token()
        res = httpx.post(
            llm._endpoint(),
            headers={"Authorization": f"Bearer {token}", "X-Goog-User-Project": llm.PROJECT},
            json=body,
            timeout=40,
        )
    except llm.ProfileError as e:
        raise InsightError(str(e)) from e
    except httpx.HTTPError as e:
        raise InsightError(f"Gemini request failed: {type(e).__name__}") from e
    if res.status_code != 200:
        raise InsightError(f"Gemini returned HTTP {res.status_code}.")
    try:
        parts = res.json()["candidates"][0]["content"]["parts"]
        text = "".join(p.get("text", "") for p in parts).strip()
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise InsightError("Gemini returned a response this service could not read.") from e
    return {"summary": text, "model": llm.MODEL, "facts": facts}
