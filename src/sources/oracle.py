"""Oracle Linux advisory fetcher using el-errata mailing list and ELSA pages."""

from __future__ import annotations

import gzip
import io
import logging
import re
from datetime import date
from typing import Optional

from bs4 import BeautifulSoup

from ..models import DistroAdvisory, DistroStatus
from .base import BaseFetcher

logger = logging.getLogger(__name__)


class OracleFetcher(BaseFetcher):
    """Fetch Oracle Linux (UEK) security advisories."""

    def __init__(self, name: str, params: dict):
        super().__init__(name, params)
        self.errata_base = params.get("errata_base", "https://linux.oracle.com/errata")
        self.mailing_list = params.get("mailing_list", "https://oss.oracle.com/pipermail/el-errata")

    def fetch_recent_cves(self, lookback_days: int = 30) -> list[str]:
        current_year_month = date.today().strftime("%Y-%B")
        prev_year_month = date.today().replace(day=1)
        from calendar import monthrange
        if prev_year_month.month == 1:
            prev_year_month = prev_year_month.replace(year=prev_year_month.year - 1, month=12)
        else:
            prev_year_month = prev_year_month.replace(month=prev_year_month.month - 1)
        prev_ym = prev_year_month.strftime("%Y-%B")

        cve_ids = set()
        for ym in [current_year_month, prev_ym]:
            url = f"{self.mailing_list}/{ym}.txt.gz"
            resp = self._get(url)
            if resp:
                try:
                    raw = gzip.decompress(resp.content)
                    text = raw.decode("utf-8", errors="ignore")
                    for m in re.finditer(r"CVE-\d{4}-\d{4,}", text):
                        cve_ids.add(m.group(0))
                except Exception as e:
                    logger.debug("Failed to decompress mailing list: %s", e)

        return list(cve_ids)

    def get_advisory(self, cve_id: str) -> Optional[DistroAdvisory]:
        advisory = DistroAdvisory(
            distro_name=self.name,
            cve_id=cve_id,
            source_url=self.mailing_list,
        )

        cves = self.fetch_recent_cves(30)
        if cve_id not in cves:
            advisory.status = DistroStatus.UNKNOWN
            return advisory

        current_ym = date.today().strftime("%Y-%B")
        url = f"{self.mailing_list}/{current_ym}.txt.gz"
        resp = self._get(url)
        if not resp:
            return advisory

        try:
            raw = gzip.decompress(resp.content)
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return advisory

        elsa_pattern = re.compile(r"ELSA-\d{4}-\d+")
        section = ""

        blocks = re.split(r"(ELSA-\d{4}-\d+)", text)
        for i in range(1, len(blocks), 2):
            elsa_id = blocks[i]
            content = blocks[i + 1] if i + 1 < len(blocks) else ""
            if cve_id in content:
                advisory.advisory_id = elsa_id
                advisory.advisory_url = f"{self.errata_base}/{elsa_id}.html"
                advisory.status = DistroStatus.FIXED

                date_match = re.search(r"(\d{4}-\d{2}-\d{2})", content[:500])
                if date_match:
                    try:
                        advisory.fix_date = date.fromisoformat(date_match.group(0))
                    except ValueError:
                        pass

                ver_match = re.search(r"kernel-(uek\d?-)?(\S+)", content)
                if ver_match:
                    advisory.kernel_version = ver_match.group(0)
                break

        return advisory
