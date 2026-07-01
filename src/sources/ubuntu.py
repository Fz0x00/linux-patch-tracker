"""Ubuntu advisory fetcher using CVE pages and USN RSS."""

from __future__ import annotations

import logging
import re
from datetime import date
from typing import Optional

from bs4 import BeautifulSoup

from ..models import DistroAdvisory, DistroStatus
from .base import BaseFetcher

logger = logging.getLogger(__name__)


class UbuntuFetcher(BaseFetcher):
    """Fetch Ubuntu security advisories."""

    def __init__(self, name: str, params: dict):
        super().__init__(name, params)
        self.cve_url = params.get("cve_url", "https://ubuntu.com/security")
        self.usn_rss = params.get("usn_rss", "https://ubuntu.com/security/notices/rss.xml")

    def fetch_recent_cves(self, lookback_days: int = 30) -> list[str]:
        resp = self._get(self.usn_rss)
        if not resp:
            return []

        cve_ids = set()
        text = resp.text
        for m in re.finditer(r"CVE-\d{4}-\d{4,}", text):
            cve_ids.add(m.group(0))

        return list(cve_ids)

    def get_advisory(self, cve_id: str) -> Optional[DistroAdvisory]:
        url = f"{self.cve_url}/{cve_id}"
        resp = self._get(url)
        if not resp:
            return None

        soup = BeautifulSoup(resp.text, "lxml")
        advisory = DistroAdvisory(
            distro_name=self.name,
            cve_id=cve_id,
            source_url=url,
        )

        release_codename = "noble" if "24.04" in self.name else "jammy"

        for row in soup.select("tr"):
            cells = row.find_all("td")
            if len(cells) >= 2:
                release_text = cells[0].get_text(strip=True).lower()
                if release_codename not in release_text:
                    continue
                status_text = cells[-1].get_text(strip=True).lower()
                if "ignored" in status_text or "not affected" in status_text or "needed" in status_text:
                    advisory.status = DistroStatus.NOT_AFFECTED if "not affected" in status_text else DistroStatus.PENDING
                    break

                version_match = re.search(r"(\d+\.\d+\.\d+-\d+\.\d+)", cells[-1].get_text())
                if version_match:
                    advisory.status = DistroStatus.FIXED
                    advisory.kernel_version = version_match.group(1)
                    break

        usn_links = soup.find_all("a", href=re.compile(r"/security/notices/USN-"))
        if usn_links:
            advisory.advisory_id = usn_links[0].get_text(strip=True)
            advisory.advisory_url = f"https://ubuntu.com{usn_links[0]['href']}"

            if advisory.status == DistroStatus.FIXED:
                date_str = re.search(r"\d{4}-\d{2}-\d{2}", resp.text)
                if date_str:
                    try:
                        advisory.fix_date = date.fromisoformat(date_str.group(0))
                    except ValueError:
                        pass

        return advisory
