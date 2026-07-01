"""Aliyun (Alibaba Cloud Linux) advisory fetcher using XML/RSS feeds."""

from __future__ import annotations

import logging
import re
from datetime import date
from typing import Optional

from bs4 import BeautifulSoup

from ..models import DistroAdvisory, DistroStatus
from .base import BaseFetcher

logger = logging.getLogger(__name__)


class AliyunFetcher(BaseFetcher):
    """Fetch Aliyun security advisories."""

    def __init__(self, name: str, params: dict):
        super().__init__(name, params)
        self.rss_url = params.get("rss_url", "https://mirrors.aliyun.com/alinux/cve/rss.xml")
        self.xml_base = params.get("xml_base", "https://mirrors.aliyun.com/alinux/cve")

    def fetch_recent_cves(self, lookback_days: int = 30) -> list[str]:
        """Fetch recent kernel-related CVEs from Aliyun RSS.

        Filters to only include kernel-related advisories.
        """
        resp = self._get(self.rss_url)
        if not resp:
            return []

        cve_ids = set()
        try:
            soup = BeautifulSoup(resp.text, "xml")
            for item in soup.find_all("item"):
                text = item.get_text()
                # Only include kernel-related advisories
                if "kernel" not in text.lower():
                    continue
                for m in re.finditer(r"CVE-\d{4}-\d{4,}", text):
                    cve_ids.add(m.group(0))
        except Exception:
            text = resp.text
            if "kernel" in text.lower():
                for m in re.finditer(r"CVE-\d{4}-\d{4,}", text):
                    cve_ids.add(m.group(0))

        return list(cve_ids)[:200]

    def get_advisory(self, cve_id: str) -> Optional[DistroAdvisory]:
        advisory = DistroAdvisory(
            distro_name=self.name,
            cve_id=cve_id,
            source_url=self.rss_url,
        )

        resp = self._get(self.rss_url)
        if not resp:
            return advisory

        try:
            soup = BeautifulSoup(resp.text, "xml")
        except Exception:
            return advisory

        for item in soup.find_all("item"):
            text = item.get_text()
            if cve_id in text:
                link_tag = item.find("link")
                pub_tag = item.find("pubDate")

                if link_tag:
                    link = link_tag.get_text(strip=True)
                    advisory.advisory_url = link
                    sa_match = re.search(r"alinux2-sa-(\d{6})", link.lower())
                    if sa_match:
                        advisory.advisory_id = f"ALINUX2-SA-{sa_match.group(1)}"
                        xml_url = f"{self.xml_base}/alinux2-sa-{sa_match.group(1)}.xml"
                        xml_resp = self._get(xml_url)
                        if xml_resp:
                            advisory = self._parse_xml_advisory(xml_resp.text, cve_id, advisory)
                            break

                if pub_tag:
                    pub_text = pub_tag.get_text(strip=True)
                    date_match = re.search(r"(\d{4})-(\d{2})-(\d{2})", pub_text)
                    if date_match:
                        try:
                            advisory.fix_date = date.fromisoformat(date_match.group(0))
                            advisory.status = DistroStatus.FIXED
                        except ValueError:
                            pass
                break

        return advisory

    def _parse_xml_advisory(self, xml_text: str, cve_id: str, advisory: DistroAdvisory) -> DistroAdvisory:
        try:
            soup = BeautifulSoup(xml_text, "xml")
            for pkg in soup.find_all("package"):
                name = pkg.find("name")
                if name and "kernel" in name.get_text().lower():
                    ver = pkg.find("version")
                    if ver:
                        advisory.kernel_version = ver.get_text(strip=True)
                    advisory.status = DistroStatus.FIXED
                    break

            date_tag = soup.find("date")
            if date_tag:
                date_str = date_tag.get_text(strip=True)
                date_match = re.search(r"(\d{4}-\d{2}-\d{2})", date_str)
                if date_match:
                    try:
                        advisory.fix_date = date.fromisoformat(date_match.group(0))
                    except ValueError:
                        pass
        except Exception as e:
            logger.debug("Failed to parse Aliyun XML: %s", e)

        return advisory
