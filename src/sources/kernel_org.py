"""kernel.org upstream stable release tracker.

Uses NVD API to find upstream fix commits, then matches against
kernel.org stable release dates from the directory listing.
"""

from __future__ import annotations

import logging
import re
from datetime import date
from typing import Optional

import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from ..models import KernelStableRelease, CVERecord

logger = logging.getLogger(__name__)

KERNEL_ORG_BASE = "https://cdn.kernel.org/pub/linux/kernel"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
VERSION_PATTERN = re.compile(r"(\d+\.\d+\.\d+)")


def fetch_stable_releases(series_list: list[str], limit_per_series: int = 10) -> list[KernelStableRelease]:
    """Fetch latest stable releases from kernel.org directory listing.

    Args:
        series_list: e.g. ["v7.x", "v6.x"]
        limit_per_series: Max number of recent releases to fetch per series.

    Returns:
        List of KernelStableRelease sorted by version (newest first).
    """
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
                # Skip rc/patch versions
                if "rc" in version or "-" in version.split(".")[0]:
                    continue
                changelogs.append((version, url + href, text))

        for version, changelog_url, raw_date in changelogs[:limit_per_series]:
            parsed_date = _parse_listing_date(raw_date)
            releases.append(
                KernelStableRelease(
                    version=version,
                    release_date=parsed_date,
                    changelog_url=changelog_url,
                )
            )

    releases.sort(key=lambda r: r.release_date, reverse=True)
    return releases


def fetch_cves_from_changelog(version: str, series: str) -> list[str]:
    """Download and parse a ChangeLog file, return CVE IDs found.

    Note: ChangeLog files can be very large (1-5 MB). Use sparingly.

    Returns:
        List of unique CVE IDs.
    """
    url = f"{KERNEL_ORG_BASE}/{series}/ChangeLog-{version}"
    try:
        resp = requests.get(url, timeout=30)
        if not resp.ok:
            return []
        return list(set(CVE_PATTERN.findall(resp.text)))
    except requests.RequestException as e:
        logger.warning("Failed to fetch ChangeLog %s: %s", version, e)
        return []


def get_upstream_fix_from_nvd(cve_id: str) -> tuple[Optional[date], str]:
    """Try to get upstream fix version from NVD.

    Returns:
        (fix_date_hint, upstream_version) — date may be None.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        resp = requests.get(url, timeout=15)
        if not resp.ok:
            return None, ""

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None, ""

        cve_data = vulnerabilities[0].get("cve", {})

        # Try to find a version from references or description
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                text = desc.get("value", "")
                # Look for commit hash references
                break

        # Check for fix version in configurations
        fix_ver = ""
        configs = cve_data.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable") == False:
                        ver = cpe_match.get("criteria", "")
                        # CPE format: cpe:2.3:o:linux:linux_kernel:6.6.137:*:*:*:*:*:*:*
                        parts = ver.split(":")
                        if len(parts) >= 6 and "linux" in parts[3]:
                            fix_ver = parts[5]
                            break

        # Try references for kernel.org changelog
        pub_date_str = cve_data.get("published", "")
        fix_date = None
        if pub_date_str:
            try:
                fix_date = date_parser.parse(pub_date_str).date()
            except Exception:
                pass

        return fix_date, fix_ver
    except Exception as e:
        logger.debug("NVD lookup failed for %s: %s", cve_id, e)
        return None, ""


def get_upstream_fix_date(
    cve_id: str,
    stable_releases: list[KernelStableRelease],
    max_changelog_fetches: int = 5,
) -> tuple[Optional[date], str, str]:
    """Find the upstream stable release date for a CVE.

    Strategy:
    1. First try NVD for a quick fix version lookup
    2. Match against known stable releases
    3. If still unknown, download ChangeLogs for recent releases

    Returns:
        (fix_date, upstream_version, changelog_url) or (None, "", "")
    """
    # Strategy 1: Try NVD
    nvd_date, nvd_ver = get_upstream_fix_from_nvd(cve_id)
    if nvd_ver:
        # Match against known stable releases
        for release in stable_releases:
            if nvd_ver in release.version or release.version.startswith(nvd_ver):
                return release.release_date, release.version, release.changelog_url

    # Strategy 2: Download recent ChangeLogs (expensive, limit it)
    checked = 0
    series_map = {}
    for r in stable_releases:
        major = r.version.split(".")[0]
        series_map.setdefault(major, []).append(r)

    for major in sorted(series_map.keys(), reverse=True):
        if checked >= max_changelog_fetches:
            break
        series = f"v{major}.x" if int(major) >= 3 else f"v{major}.x"
        for release in series_map[major]:
            if checked >= max_changelog_fetches:
                break
            cves = fetch_cves_from_changelog(release.version, series)
            checked += 1
            if cve_id in cves:
                return release.release_date, release.version, release.changelog_url

    # Fallback: use NVD date
    if nvd_date:
        return nvd_date, nvd_ver, ""

    return None, "", ""


def _parse_listing_date(text: str) -> date:
    """Parse date from Apache directory listing text like '2026-05-07 14:30'."""
    try:
        parts = text.split()
        if len(parts) >= 2:
            return date_parser.parse(parts[0]).date()
        return date_parser.parse(text).date()
    except (ValueError, date_parser.ParserError):
        return date.today()
