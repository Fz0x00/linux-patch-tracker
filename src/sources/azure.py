"""Azure Linux advisory fetcher using RPM repository metadata.

Since Azure Linux has no public per-CVE advisory page, we infer
patch dates from kernel package build timestamps in the RPM repository.
"""

from __future__ import annotations

import gzip
import logging
import re
import xml.etree.ElementTree as ET
from datetime import date, datetime
from typing import Optional

from ..models import DistroAdvisory, DistroStatus
from .base import BaseFetcher

logger = logging.getLogger(__name__)

NS = {"repo": "http://linux.duke.edu/metadata/repo", "rpm": "http://linux.duke.edu/metadata/rpm"}
REPO_NS = "{http://linux.duke.edu/metadata/repo}"
COMMON_NS = "{http://linux.duke.edu/metadata/common}"
RPM_NS = "{http://linux.duke.edu/metadata/rpm}"


class AzureFetcher(BaseFetcher):
    """Fetch Azure Linux kernel versions from RPM repo metadata."""

    def __init__(self, name: str, params: dict):
        super().__init__(name, params)
        self.repo_url = params.get("repo_url", "")
        self.kernel_series = params.get("kernel_series", "")

    def fetch_recent_cves(self, lookback_days: int = 30) -> list[str]:
        return []

    def get_advisory(self, cve_id: str) -> Optional[DistroAdvisory]:
        return None

    def get_latest_kernel_info(self) -> dict:
        """Return latest kernel version and build date from the repo.

        Returns:
            dict with 'version', 'build_date', 'repo_url' keys.
        """
        repomd_url = f"{self.repo_url}/repodata/repomd.xml"
        resp = self._get(repomd_url)
        if not resp:
            return {}

        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError:
            return {}

        primary_href = None
        for data_elem in root.findall(REPO_NS + "data"):
            dtype = data_elem.get("type", "")
            if dtype == "primary":
                location = data_elem.find(REPO_NS + "location")
                if location is not None:
                    primary_href = location.get("href")
                break

        if not primary_href:
            return {}

        primary_url = f"{self.repo_url}/{primary_href}"
        resp = self._get(primary_url)
        if not resp:
            return {}

        try:
            decompressed = gzip.decompress(resp.content)
            root = ET.fromstring(decompressed)
        except Exception as e:
            logger.error("Failed to parse Azure repo primary.xml: %s", e)
            return {}

        latest_version = ""
        latest_build_ts = 0

        for pkg in root:
            name_elem = pkg.find(COMMON_NS + "name")
            if name_elem is None or name_elem.text != "kernel":
                continue

            version_elem = pkg.find(COMMON_NS + "version")
            time_elem = pkg.find(COMMON_NS + "time")

            if version_elem is None or time_elem is None:
                continue

            ver_str = f"{version_elem.get('ver')}-{version_elem.get('rel')}"
            build_ts = int(time_elem.get("build", "0"))

            if not self.kernel_series or ver_str.startswith(self.kernel_series):
                if build_ts > latest_build_ts:
                    latest_build_ts = build_ts
                    latest_version = ver_str

        if latest_build_ts:
            build_date = datetime.fromtimestamp(latest_build_ts).date()
            return {
                "version": latest_version,
                "build_date": build_date,
                "repo_url": self.repo_url,
                "method": "rpm_repo_inferred",
            }

        return {}

    def get_kernel_history(self) -> list[dict]:
        """Return all kernel versions and build dates from the repo.

        Returns:
            List of dicts with 'version' and 'build_date', sorted newest first.
        """
        repomd_url = f"{self.repo_url}/repodata/repomd.xml"
        resp = self._get(repomd_url)
        if not resp:
            return []

        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError:
            return []

        primary_href = None
        for data_elem in root.findall(REPO_NS + "data"):
            if data_elem.get("type") == "primary":
                location = data_elem.find(REPO_NS + "location")
                if location is not None:
                    primary_href = location.get("href")
                break

        if not primary_href:
            return []

        primary_url = f"{self.repo_url}/{primary_href}"
        resp = self._get(primary_url)
        if not resp:
            return []

        try:
            decompressed = gzip.decompress(resp.content)
            root = ET.fromstring(decompressed)
        except Exception as e:
            logger.error("Failed to parse Azure repo: %s", e)
            return []

        history = []
        for pkg in root:
            name_elem = pkg.find(COMMON_NS + "name")
            if name_elem is None or name_elem.text != "kernel":
                continue

            version_elem = pkg.find(COMMON_NS + "version")
            time_elem = pkg.find(COMMON_NS + "time")
            if version_elem is None or time_elem is None:
                continue

            ver_str = f"{version_elem.get('ver')}-{version_elem.get('rel')}"
            build_ts = int(time_elem.get("build", "0"))

            if not self.kernel_series or ver_str.startswith(self.kernel_series):
                build_date = datetime.fromtimestamp(build_ts).date()
                history.append({"version": ver_str, "build_date": build_date})

        history.sort(key=lambda x: x["build_date"], reverse=True)
        return history
