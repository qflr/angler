"""Ask Vertex Gemini for a decoy profile. The result is data: paths and static response text.

Nothing returned here is installed on the honeypot. The sensor keeps its own fixed profiles.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import httpx

SA_FILE = Path(__file__).resolve().parents[1] / ".gemini_sa.json"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

# This machine's GOOGLE_CLOUD_PROJECT is a different, unbilled project. Angler bills the decoy project.
PROJECT = os.getenv("ANGLER_GCP_PROJECT", "project-6697f472-fcf5-402d-a67")
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
LOCATION = os.getenv("GEMINI_LOCATION", "global")

# Scanner paths often carry a query string, so "?" is allowed; still no "..", spaces or control characters.
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,159}$")
_TYPES = {"text/plain", "text/html", "application/json"}


class ProfileError(Exception):
    """Gemini did not return a usable profile. The job stays failed."""


def _service_account_token() -> str | None:
    """A service-account key does not expire. Render sets GEMINI_SA_JSON; locally the file is enough."""
    raw = os.getenv("GEMINI_SA_JSON", "").strip()
    if not raw and SA_FILE.exists() and SA_FILE.stat().st_size > 0:
        raw = SA_FILE.read_text(encoding="utf-8")
    if not raw:
        return None
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request

    creds = service_account.Credentials.from_service_account_info(json.loads(raw), scopes=SCOPES)
    creds.refresh(Request())
    return creds.token


def access_token() -> str:
    """Prefer the service-account key. GEMINI_ACCESS_TOKEN is an hour-long fallback."""
    sa = _service_account_token()
    if sa:
        return sa
    env = os.getenv("GEMINI_ACCESS_TOKEN", "").strip()
    if env:
        return env
    exe = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    if not exe:
        raise ProfileError("Gemini is not configured on this service.")
    try:
        out = subprocess.run(
            [exe, "auth", "print-access-token", f"--project={PROJECT}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as e:
        raise ProfileError("Gemini is not configured on this service.") from e
    token = out.stdout.strip()
    if not token:
        raise ProfileError("Gemini is not configured on this service.")
    return token


def _endpoint() -> str:
    host = "aiplatform.googleapis.com" if LOCATION == "global" else f"{LOCATION}-aiplatform.googleapis.com"
    return (
        f"https://{host}/v1/projects/{PROJECT}/locations/{LOCATION}"
        f"/publishers/google/models/{MODEL}:generateContent"
    )


def validate(cve_id: str, raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ProfileError("Gemini returned a profile that was not an object.")
    summary = raw.get("summary")
    responses = raw.get("responses")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 180:
        raise ProfileError("Gemini returned a profile with no usable summary.")
    if not isinstance(responses, list) or not 1 <= len(responses) <= 4:
        raise ProfileError("Gemini returned a profile with an unexpected response list.")
    cleaned = []
    for item in responses:
        if not isinstance(item, dict):
            raise ProfileError("Gemini returned a profile entry that was not an object.")
        path = item.get("path")
        status = item.get("status")
        content_type = item.get("content_type")
        body = item.get("body", "")
        if not isinstance(path, str) or not _PATH.match(path) or ".." in path:
            raise ProfileError("Gemini returned a profile with a path this decoy will not keep.")
        if not isinstance(status, int) or not 200 <= status <= 599:
            raise ProfileError("Gemini returned a profile with a bad status code.")
        if content_type not in _TYPES:
            raise ProfileError("Gemini returned a profile with a content type this decoy will not keep.")
        if not isinstance(body, str) or "\x00" in body or len(body) > 200:
            raise ProfileError("Gemini returned a profile body this decoy will not keep.")
        cleaned.append({"path": path, "status": status, "content_type": content_type, "body": body})
    return {"summary": summary.strip(), "responses": cleaned}


def render(cve_id: str, profile: dict) -> str:
    lines = [
        f"Gemini proposed a profile for {cve_id}. It is not installed on the decoy.",
        profile["summary"],
    ]
    lines += [f"{item['path']} -> {item['status']} {item['content_type']}" for item in profile["responses"]]
    return "\n".join(lines)


def _parse(text: str, cve_id: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.S)
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        raise ProfileError("Gemini returned a profile that was not JSON.") from e
    if isinstance(raw, dict) and raw.get("cve_id") not in (None, cve_id):
        raise ProfileError("Gemini returned a profile for a different CVE.")
    return validate(cve_id, raw)


def propose(cve_id: str, description: str) -> dict:
    """One Vertex call. Raises ProfileError. Does not touch the honeypot."""
    token = access_token()
    prompt = (
        "Propose a honeypot profile for this CVE. Return JSON only, no markdown.\n"
        '{"summary":"one sentence, at most 160 characters",'
        '"responses":[{"path":"/starts-with-slash","status":200,'
        '"content_type":"text/plain","body":"static text, at most 160 characters"}]}\n'
        "1 to 4 responses. Paths are what a scanner would request. "
        "Bodies are short static text a server would return. "
        "content_type is text/plain, text/html, or application/json.\n"
        f"CVE: {cve_id}\n"
        f"Advisory: {description[:500] or 'unknown'}"
    )
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2048,
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingBudget": 0},
        },
    }
    try:
        res = httpx.post(
            _endpoint(),
            headers={"Authorization": f"Bearer {token}", "X-Goog-User-Project": PROJECT},
            json=body,
            timeout=30,
        )
    except httpx.HTTPError as e:
        raise ProfileError(f"Gemini request failed: {type(e).__name__}") from e
    if res.status_code == 401:
        raise ProfileError("Gemini rejected the access token. It expires about an hour after it is minted.")
    if res.status_code != 200:
        raise ProfileError(f"Gemini returned HTTP {res.status_code}.")
    try:
        parts = res.json()["candidates"][0]["content"]["parts"]
        text = "".join(part.get("text", "") for part in parts)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as e:
        raise ProfileError("Gemini returned a response this service could not read.") from e
    return _parse(text, cve_id)
