"""RHEL (Red Hat) advisory fetcher using the hydra REST API."""

from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Optional

from ..models import DistroAdvisory, DistroStatus
from .base import BaseFetcher

logger = logging.getLogger(__name__)


class RHELFetcher(BaseFetcher):
    """Fetch RHEL security advisories via access.redhat.com REST API."""

    def __init__(self, name: str, params: dict):
        super().__init__(name, params)
        self.api_url = params.get("api_url", "https://access.redhat.com/hydra/rest/securitydata")
        self.product_filter = params.get("product_filter", "")

    def fetch_recent_cves(self, lookback_days: int = 30) -> list[str]:
        """Fetch recent kernel CVEs from RHEL CVE list API."""
        url = f"{self.api_url}/cve.json"
        after_date = (date.today() - timedelta(days=lookback_days)).isoformat()
        params = {
            "after": after_date,
            "per_page": 200,
            "package": "kernel",
        }

        resp = self._get(url, params=params)
        if not resp:
            return []

        cve_ids = []
        try:
            data = resp.json()
            for item in data:
                cve_id = item.get("CVE")
                if cve_id:
                    cve_ids.append(cve_id)
        except Exception as e:
            logger.error("Failed to parse RHEL CVE list: %s", e)

        return cve_ids

    def get_advisory(self, cve_id: str) -> Optional[DistroAdvisory]:
        """Get RHEL advisory details for a CVE."""
        url = f"{self.api_url}/cve/{cve_id}.json"
        resp = self._get(url)
        if not resp:
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        affected_releases = data.get("affected_release", [])
        if not isinstance(affected_releases, list):
            affected_releases = [affected_releases]

        for release in affected_releases:
            product = release.get("product_name", "")
            if self.product_filter and self.product_filter not in product:
                continue

            if "kernel" not in release.get("package", "").lower():
                continue

            fix_date_str = release.get("release_date", "")
            try:
                fix_date = date.fromisoformat(fix_date_str[:10])
            except (ValueError, IndexError):
                fix_date = None

            return DistroAdvisory(
                distro_name=self.name,
                cve_id=cve_id,
                status=DistroStatus.FIXED,
                advisory_id=release.get("advisory", ""),
                advisory_url=f"https://access.redhat.com/errata/{release.get('advisory', '')}.html",
                kernel_version=release.get("package", ""),
                fix_date=fix_date,
                source_url=url,
            )

        if data.get("state") and "not affected" in str(data.get("statement", "")).lower():
            return DistroAdvisory(
                distro_name=self.name,
                cve_id=cve_id,
                status=DistroStatus.NOT_AFFECTED,
                source_url=url,
            )

        return DistroAdvisory(
            distro_name=self.name,
            cve_id=cve_id,
            status=DistroStatus.PENDING,
            source_url=url,
        )
