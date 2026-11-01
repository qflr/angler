"""Noise vs targeted, and how far along the kill chain a request got.

    targeted  the request carries a probe or exploit for a CVE our decoy impersonates
    noise     everything else: crawlers, generic scanners, exploits for software we don't pretend to be

Stage: recon (looking around), probe (checking for a specific weakness), exploit (carries a payload).
Plain signature rules on the raw request; transparent and easy to defend on stage.
"""

import re
from urllib.parse import unquote_plus

# CVEs the decoy impersonates, with what a probe vs an exploit for each looks like.
OUR_CVES = {
    "CVE-2024-4577": {
        # PHP-CGI argument injection: "-d allow_url_include=1 -d auto_prepend_file=php://input",
        # usually with a soft hyphen (%AD) standing in for "-" to beat the CVE-2012-1823 fix.
        "match": re.compile(r"allow_url_include|auto_prepend_file|php-cgi(\.exe)?|%ad[ds]\b|\xadd", re.I),
        # Naming php://input is still a probe; a payload means actual PHP code arrived.
        "exploit": re.compile(r"<\?php|data:[^ ]*base64|system\(|shell_exec|passthru|exec\(|eval\(", re.I),
    },
}

# Exploit-shaped requests for other software: payloads, but not aimed at us.
EXPLOIT_TEXT = re.compile(
    r"\$\{jndi:|/bin/(ba)?sh|cmd\.exe|powershell|wget\s|curl\s|\.\./\.\.|%2e%2e|<\?php|base64_decode|"
    r"eval-stdin\.php|invokefunction|;\s*(id|uname)|\|\s*(id|sh)\b",
    re.I,
)
# Looking for a specific weakness or leaked secret.
PROBE_TEXT = re.compile(
    r"\.env\b|\.git/|wp-login|wp-admin|xmlrpc|phpmyadmin|phpinfo|config\.(php|json|ya?ml)|\.aws/|"
    r"actuator|/admin|/login|/cgi-bin/|\.(sql|bak|zip|tar\.gz)\b|server-status|/vendor/|/console",
    re.I,
)


def classify(method: str, path: str, body: str, headers: dict | None = None) -> dict:
    """Returns {classification, stage, cve_id}."""
    raw = f"{path}\n{body}"
    decoded = unquote_plus(raw, encoding="latin-1")
    header_text = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    haystack = f"{raw}\n{decoded}\n{header_text}"

    for cve_id, sig in OUR_CVES.items():
        if sig["match"].search(haystack):
            stage = "exploit" if sig["exploit"].search(haystack) else "probe"
            return {"classification": "targeted", "stage": stage, "cve_id": cve_id}

    if EXPLOIT_TEXT.search(haystack):
        stage = "exploit"
    elif PROBE_TEXT.search(decoded) or method not in ("GET", "HEAD"):
        stage = "probe"
    else:
        stage = "recon"
    return {"classification": "noise", "stage": stage, "cve_id": None}
