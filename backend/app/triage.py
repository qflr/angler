"""Our triage priority for a CVE (the build plan's prioritization view, scraping plan section 6).

    urgent  listed in CISA KEV: someone is exploiting it in the wild right now
    high    no complete fix yet + code execution + reachable remotely + CVSS >= 7 (or unscored)
    watch   everything else

Inputs are only what the pipeline stored; no model, no guessing beyond these documented rules.
"""

import json
import re

# Weaknesses that usually mean the attacker ends up running code.
RCE_CWES = {"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-434", "CWE-502", "CWE-917", "CWE-1336"}
RCE_TEXT = re.compile(
    r"remote code execution|arbitrary (code|command)s?|command injection|code injection|execute (arbitrary )?(code|commands)",
    re.I,
)
# Titles that carry no information on their own ("Security Advisory 0199", "CVE-2026-1234").
EMPTY_TITLE = re.compile(r"^((security )?(advisory|bulletin)\b|cve-\d)", re.I)
REMOTE_TEXT = re.compile(r"\bremote(ly)?\b|unauthenticated|network|crafted (http )?request|over the internet", re.I)


def status(
    kev: bool, patch_status: str | None, cwes_json: str | None, description: str | None, cvss: float | None = None
) -> str:
    if kev:
        return "urgent"
    text = description or ""
    rce = bool(RCE_CWES & set(json.loads(cwes_json or "[]"))) or bool(RCE_TEXT.search(text))
    # The CVSS floor stops e.g. XSS that a CNA also tagged CWE-94 from reading as code execution.
    serious = cvss is None or cvss >= 7.0
    if patch_status != "patched" and rce and serious and REMOTE_TEXT.search(text):
        return "high"
    return "watch"


def summary(title: str | None, description: str | None, limit: int = 240) -> str:
    """One line: the CNA's title if it gave one, else the description's first sentence."""
    title = (title or "").strip()
    if EMPTY_TITLE.match(title) or len(title.split()) < 3:
        title = ""
    text = title or (description or "").strip()
    text = " ".join(text.split())
    first = re.split(r"(?<=[.!?])\s+", text, maxsplit=1)[0]
    return first if len(first) <= limit else first[: limit - 1].rstrip() + "…"


def product(vendor: str | None, product_name: str | None) -> str | None:
    vendor = None if (vendor or "").strip().lower() in ("", "n/a", "unknown") else vendor
    if not product_name:
        return vendor
    if not vendor or product_name.lower().startswith(vendor.lower()):
        return product_name
    return f"{vendor} {product_name}"
