"""Response models for the four dashboard endpoints.

Mirrors docs/api-contract.md and frontend/src/data/types.ts. Change all three together.
"""

from typing import Literal, Optional

from pydantic import BaseModel

Classification = Literal["noise", "targeted"]
Stage = Literal["recon", "probe", "exploit"]
SourceTag = Literal["tor", "vpn", "cloud", "residential", "scanner"]


class Cve(BaseModel):
    id: str
    description: str
    severity: Literal["critical", "high", "medium", "low", "unknown"]
    status: Literal["urgent", "high", "watch"]
    kev: bool
    patch_status: Literal["patched", "partial", "unpatched", "unknown"]
    cvss: Optional[float] = None
    product: Optional[str] = None
    published: Optional[str] = None


class AttackEvent(BaseModel):
    id: str
    source_ip: str
    asn: int
    port: int
    timestamp: str
    classification: Classification
    org: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    cve_id: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    stage: Optional[Stage] = None
    actor_id: Optional[str] = None


class Stats(BaseModel):
    new_cves: int
    updated_cves: int
    newly_patched: int
    newly_kev: int
    total_hits: int
    window: Optional[str] = None


class Actor(BaseModel):
    id: str
    label: str
    ips: list[str]
    asns: list[int]
    classification: Classification
    hit_count: int
    first_seen: str
    last_seen: str
    countries: Optional[list[str]] = None
    tags: Optional[list[SourceTag]] = None
    timezone: Optional[str] = None
    cves: Optional[list[str]] = None
