"""Debian advisory fetcher using the security tracker."""

from __future__ import annotations

import logging
import re
from datetime import date
from typing import Optional

from bs4 import BeautifulSoup

from ..models import DistroAdvisory, DistroStatus
from .base import BaseFetcher

logger = logging.getLogger(__name__)


class DebianFetcher(BaseFetcher):
    """Fetch Debian security advisories via security-tracker."""

    def __init__(self, name: str, params: dict):
        super().__init__(name, params)
        self.tracker_url = params.get("tracker_url", "https://security-tracker.debian.org/tracker")

    def fetch_recent_cves(self, lookback_days: int = 30) -> list[str]:
        url = f"{self.tracker_url}/status/release-testing"
        resp = self._get(url)
        if not resp:
            return []

        soup = BeautifulSoup(resp.text, "lxml")
        cve_ids = []
        for row in soup.select("tr"):
            cell = row.find("td")
            if cell:
                text = cell.get_text(strip=True)
                m = re.match(r"CVE-\d{4}-\d{4,}", text)
                if m:
                    cve_ids.append(m.group(0))

        return list(set(cve_ids))[:200]

    def get_advisory(self, cve_id: str) -> Optional[DistroAdvisory]:
        url = f"{self.tracker_url}/{cve_id}"
        resp = self._get(url)
        if not resp:
            return DistroAdvisory(
                distro_name=self.name, cve_id=cve_id, status=DistroStatus.UNKNOWN, source_url=url
            )

        soup = BeautifulSoup(resp.text, "lxml")
        advisory = DistroAdvisory(
            distro_name=self.name,
            cve_id=cve_id,
            source_url=url,
        )

        for row in soup.select("tr"):
            cells = row.find_all("td")
            if len(cells) >= 3:
                release = cells[0].get_text(strip=True).lower()
                if "trixie" not in release and "sid" not in release:
                    continue
                status_text = cells[1].get_text(strip=True).lower()
                version_text = cells[2].get_text(strip=True) if len(cells) > 2 else ""

                if "fixed" in status_text or re.search(r"\d+\.\d+", version_text):
                    advisory.status = DistroStatus.FIXED
                    advisory.kernel_version = version_text
                elif "vulnerable" in status_text or "open" in status_text:
                    advisory.status = DistroStatus.PENDING

        dsa_link = soup.find("a", href=re.compile(r"/tracker/DSA-"))
        if dsa_link:
            advisory.advisory_id = dsa_link.get_text(strip=True)
            advisory.advisory_url = f"https://security-tracker.debian.org{dsa_link['href']}"
            dsa_page = self._get(advisory.advisory_url)
            if dsa_page:
                date_match = re.search(r"(\d{4}-\d{2}-\d{2})", dsa_page.text)
                if date_match:
                    try:
                        advisory.fix_date = date.fromisoformat(date_match.group(0))
                    except ValueError:
                        pass

        return advisory
