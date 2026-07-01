"""kernel.org upstream stable release tracker.

Uses local SQLite cache for CVE-to-version mappings.
Downloads ChangeLogs once, parses CVE IDs, stores in DB.
"""

from __future__ import annotations

import logging
import re
from datetime import date
from typing import Optional

import requests
from bs4 import BeautifulSoup

from ..models import KernelStableRelease

logger = logging.getLogger(__name__)

KERNEL_ORG_BASE = "https://cdn.kernel.org/pub/linux/kernel"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")


def fetch_stable_releases(series_list: list[str], limit_per_series: int = 10) -> list[KernelStableRelease]:
    """Fetch latest stable releases from kernel.org directory listing.

    Args:
        series_list: e.g. ["v7.x", "v6.x"]
        limit_per_series: Max number of recent releases to fetch per series.

    Returns:
        List of KernelStableRelease sorted by version (newest first).
    """
    from dateutil import parser as date_parser

    releases = []
    for series in series_list:
        url = f"{KERNEL_ORG_BASE}/{series}/"
        try:
            resp = requests.get(url, timeout=15)
            if not resp.ok:
                logger.warning("Failed to fetch kernel.org listing: %s", url)
                continue
        except requests.RequestException:
            continue

        soup = BeautifulSoup(resp.text, "lxml")
        changelogs = []
        for link in soup.find_all("a"):
            href = link.get("href", "")
            text = link.get_text(strip=True)
            if href.startswith("ChangeLog-") and not href.endswith(".sign"):
                version = href.replace("ChangeLog-", "")
                if "rc" in version or "-" in version.split(".")[0]:
                    continue
                changelogs.append((version, url + href, text))

        for version, changelog_url, raw_date in changelogs[:limit_per_series]:
            try:
                parsed_date = date_parser.parse(raw_date.split()[0]).date()
            except Exception:
                parsed_date = date.today()
            releases.append(
                KernelStableRelease(
                    version=version,
                    release_date=parsed_date,
                    changelog_url=changelog_url,
                )
            )

    releases.sort(key=lambda r: r.release_date, reverse=True)
    return releases


def get_upstream_fix_date_from_db(
    cve_id: str,
    db_conn,
) -> tuple[Optional[date], str, str]:
    """Look up upstream fix date from local SQLite cache.

    Returns:
        (fix_date, upstream_version, changelog_url) or (None, "", "")
    """
    from .cache import lookup_cve

    result = lookup_cve(db_conn, cve_id)
    if result:
        version = result["version"]
        changelog_url = f"{KERNEL_ORG_BASE}/v{version.split('.')[0]}.x/ChangeLog-{version}"
        return result["release_date"], version, changelog_url

    return None, "", ""
