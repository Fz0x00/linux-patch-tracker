"""Data models for kernel patch tracking."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from enum import Enum
from typing import Optional


class DistroStatus(str, Enum):
    FIXED = "fixed"
    PENDING = "pending"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


class AlertLevel(str, Enum):
    NONE = "none"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class KernelStableRelease:
    """An upstream kernel.org stable release."""

    version: str
    release_date: date
    changelog_url: str

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "release_date": self.release_date.isoformat(),
            "changelog_url": self.changelog_url,
        }


@dataclass
class CVERecord:
    """A CVE vulnerability record."""

    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    component: str = ""
    severity: str = ""
    published_date: Optional[date] = None
    upstream_version: str = ""
    upstream_fix_date: Optional[date] = None
    upstream_changelog_url: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        for k, v in d.items():
            if isinstance(v, date):
                d[k] = v.isoformat()
        return d


@dataclass
class DistroAdvisory:
    """A distribution-specific security advisory for a CVE."""

    distro_name: str
    cve_id: str
    status: DistroStatus = DistroStatus.UNKNOWN
    advisory_id: str = ""
    advisory_url: str = ""
    kernel_version: str = ""
    fix_date: Optional[date] = None
    delay_days: Optional[int] = None
    is_livepatch: bool = False
    source_url: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        for k, v in d.items():
            if isinstance(v, date):
                d[k] = v.isoformat()
        return d


@dataclass
class LatencyRecord:
    """A complete latency record for one CVE × one distro."""

    cve_id: str
    distro_name: str
    upstream_fix_date: Optional[date] = None
    distro_fix_date: Optional[date] = None
    delay_days: Optional[int] = None
    status: DistroStatus = DistroStatus.UNKNOWN
    kernel_version: str = ""
    advisory_id: str = ""
    advisory_url: str = ""
    alert_level: AlertLevel = AlertLevel.NONE
    source: str = ""

    @property
    def is_fast(self) -> bool:
        return self.delay_days is not None and self.delay_days < 0

    @property
    def is_delayed(self) -> bool:
        return self.delay_days is not None and self.delay_days > 14

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["alert_level"] = self.alert_level.value
        for k, v in d.items():
            if isinstance(v, date):
                d[k] = v.isoformat()
        return d

    def to_csv_row(self) -> str:
        fields = [
            self.cve_id,
            self.distro_name,
            self.upstream_fix_date.isoformat() if self.upstream_fix_date else "",
            self.distro_fix_date.isoformat() if self.distro_fix_date else "",
            str(self.delay_days) if self.delay_days is not None else "",
            self.status.value,
            self.kernel_version,
            self.advisory_id,
            self.advisory_url,
            self.source,
        ]
        return ",".join(f'"{f}"' for f in fields)


def load_cves_from_json(path: str) -> list[CVERecord]:
    with open(path) as f:
        data = json.load(f)
    return [CVERecord(**item) for item in data]


def save_cves_to_json(cves: list[CVERecord], path: str) -> None:
    with open(path, "w") as f:
        json.dump([c.to_dict() for c in cves], f, indent=2, ensure_ascii=False)
