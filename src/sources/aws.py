"""AWS Amazon Linux advisory fetcher using ALAS explore page."""

from __future__ import annotations

import logging
import re
from datetime import date
from typing import Optional

from bs4 import BeautifulSoup

from ..models import DistroAdvisory, DistroStatus
from .base import BaseFetcher

logger = logging.getLogger(__name__)

DATE_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2})")
PACKAGE_PATTERN = re.compile(r"kernel", re.IGNORECASE)


class AWSFetcher(BaseFetcher):
    """Fetch AWS Amazon Linux security advisories."""

    def __init__(self, name: str, params: dict):
        super().__init__(name, params)
        self.explore_url = params.get("explore_url", "https://explore.alas.aws.amazon.com")
        platform_tag = "AL2" if "al2" in name.lower() else "AL2023"
        self.platform_tag = platform_tag

    def fetch_recent_cves(self, lookback_days: int = 30) -> list[str]:
        """Fetch recent kernel-related CVEs from AWS ALAS.

        Uses the ALAS kernel-specific feed to avoid fetching all 25k+ CVEs.
        """
        # Use ALAS kernel security feed
        url = f"{self.explore_url}/alas2/kernel.html"
        resp = self._get(url)
        cve_ids = set()

        if resp:
            soup = BeautifulSoup(resp.text, "lxml")
            for link in soup.find_all("a", href=True):
                href = link["href"]
                m = re.search(r"CVE-\d{4}-\d{4,}", href)
                if m:
                    cve_ids.add(m.group(0))

        # Fallback: scrape the main explore page but filter
        if not cve_ids:
            resp = self._get(f"{self.explore_url}/")
            if resp:
                soup = BeautifulSoup(resp.text, "lxml")
                for row in soup.select("tr"):
                    text = row.get_text()
                    if "kernel" in text.lower() and "livepatch" not in text.lower():
                        for m in re.finditer(r"CVE-\d{4}-\d{4,}", text):
                            cve_ids.add(m.group(0))

        return list(cve_ids)[:500]

    def get_advisory(self, cve_id: str) -> Optional[DistroAdvisory]:
        url = f"{self.explore_url}/{cve_id}.html"
        resp = self._get(url)
        if not resp:
            return None

        soup = BeautifulSoup(resp.text, "lxml")
        advisory = DistroAdvisory(
            distro_name=self.name,
            cve_id=cve_id,
            source_url=url,
        )

        table = soup.find("table")
        if table:
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) >= 5:
                    platform = cells[0].get_text(strip=True)
                    package = cells[1].get_text(strip=True)
                    release_date_str = cells[2].get_text(strip=True)
                    alas_id = cells[3].get_text(strip=True)
                    status_str = cells[4].get_text(strip=True)

                    if not PACKAGE_PATTERN.search(package):
                        continue
                    platform_match = (
                        ("Amazon Linux 2" in platform and self.platform_tag == "AL2")
                        or ("Amazon Linux 2023" in platform and self.platform_tag == "AL2023")
                    )
                    if not platform_match:
                        continue

                    try:
                        fix_date = date.fromisoformat(release_date_str[:10])
                    except (ValueError, IndexError):
                        fix_date = None

                    is_livepatch = "livepatch" in package.lower()

                    advisory.status = DistroStatus.FIXED if "Fixed" in status_str else DistroStatus.PENDING
                    advisory.advisory_id = alas_id
                    advisory.advisory_url = cells[3].find("a", href=True)["href"] if cells[3].find("a", href=True) else ""
                    advisory.kernel_version = package
                    advisory.fix_date = fix_date
                    advisory.is_livepatch = is_livepatch
                    break

        if advisory.status == DistroStatus.UNKNOWN:
            desc = soup.get_text()
            if "not affected" in desc.lower() or "not impacted" in desc.lower():
                advisory.status = DistroStatus.NOT_AFFECTED

        return advisory
