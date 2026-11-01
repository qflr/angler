"""Noise vs targeted, which CVE a request goes after, and how far along the kill chain it got.

    targeted  carries a probe or exploit for a CVE our decoy impersonates (DECOY_CVES)
    noise     everything else: crawlers, generic scanners, exploits for software we don't pretend to be

cve_id is set whenever a request matches a known mass-exploited CVE signature, ours or not, so the
dashboard can show what the internet is actually spraying. Stage: recon (looking around), probe
(checking for a specific weakness), exploit (carries a payload). Plain signature rules on the raw
request; transparent and easy to defend on stage.
"""

import re
from urllib.parse import unquote_plus

# (cve_id, what it is, request signature). Mass-exploited bugs that dominate honeypot traffic.
SIGNATURES = [
    ("CVE-2023-1389", "TP-Link Archer AX21 command injection (Mirai)", r"/cgi-bin/luci/;stok=/locale"),
    ("CVE-2017-9841", "PHPUnit eval-stdin.php RCE", r"eval-stdin\.php"),
    ("CVE-2021-41773", "Apache 2.4.49/50 path traversal + CGI RCE",
     r"/(cgi-bin|icons)/(\.|%2e|%%32%65)+(%2e|\.)?/"),
    ("CVE-2024-4577", "PHP-CGI argument injection",
     r"allow_url_include|auto_prepend_file|php-cgi(\.exe)?|%ad[ds]\b|\xadd"),
    ("CVE-2021-44228", "Log4Shell JNDI injection", r"\$\{(jndi|\$\{lower:j\}|::-j)"),
    ("CVE-2018-10561", "GPON router auth bypass + RCE", r"GponForm/diag_Form"),
    ("CVE-2017-17215", "Huawei HG532 UPnP RCE", r"/ctrlt/DeviceUpgrade_1"),
    ("CVE-2018-20062", "ThinkPHP invokefunction RCE", r"invokefunction&function=call_user_func_array"),
    ("CVE-2022-1388", "F5 BIG-IP iControl REST auth bypass", r"/mgmt/tm/util/bash"),
    ("CVE-2021-36260", "Hikvision web server command injection", r"/SDK/webLanguage"),
    ("CVE-2024-3400", "PAN-OS GlobalProtect command injection", r"/ssl-vpn/hipreport\.esp"),
    ("CVE-2023-20198", "Cisco IOS XE web UI privilege escalation", r"/webui/logoutconfirm\.html\?logon_hash"),
    ("CVE-2014-6271", "Shellshock bash function injection", r"\(\)\s*\{\s*:?\s*;?\s*\}\s*;"),
]
_COMPILED = [(cve, name, re.compile(sig, re.I)) for cve, name, sig in SIGNATURES]
CVE_NAMES = {cve: name for cve, name, _ in SIGNATURES}

# CVEs the decoy answers believably (honeypot/sensor.py route()). Hits on these are "targeted".
DECOY_CVES = {"CVE-2023-1389", "CVE-2017-9841", "CVE-2021-41773", "CVE-2024-4577"}

# A payload actually arrived: code, a shell command, or a downloader.
PAYLOAD_TEXT = re.compile(
    r"<\?php|system\(|shell_exec|passthru|exec\(|eval\(|base64_decode|/bin/(ba)?sh|cmd\.exe|powershell|"
    r"\bwget\s|\bcurl\s|tftp\s|chmod\s|\$\(|`[^`]+`|;\s*(id|uname|cd|rm)\b|\|\s*(sh|bash)\b|jndi:(ldap|rmi|dns)",
    re.I,
)
# Looking for a specific weakness or leaked secret, without a CVE we recognise.
PROBE_TEXT = re.compile(
    r"\.env\b|\.git/|wp-login|wp-admin|xmlrpc|phpmyadmin|phpinfo|config\.(php|json|ya?ml)|\.aws/|"
    r"actuator|/admin|/login|/cgi-bin/|\.(sql|bak|zip|tar\.gz)\b|server-status|/vendor/|/console",
    re.I,
)


def classify(method: str, path: str, body: str, headers: dict | None = None, decoy_cves: set | None = None) -> dict:
    """Returns {classification, stage, cve_id}."""
    decoy_cves = DECOY_CVES if decoy_cves is None else decoy_cves
    raw = f"{path}\n{body}"
    decoded = unquote_plus(raw, encoding="latin-1")
    header_text = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    haystack = f"{raw}\n{decoded}\n{header_text}"
    payload = bool(PAYLOAD_TEXT.search(f"{decoded}\n{header_text}"))

    for cve_id, _, sig in _COMPILED:
        if sig.search(haystack):
            return {
                "classification": "targeted" if cve_id in decoy_cves else "noise",
                "stage": "exploit" if payload else "probe",
                "cve_id": cve_id,
            }

    if payload:
        stage = "exploit"
    elif PROBE_TEXT.search(decoded) or method not in ("GET", "HEAD"):
        stage = "probe"
    else:
        stage = "recon"
    return {"classification": "noise", "stage": stage, "cve_id": None}
