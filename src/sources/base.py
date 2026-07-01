"""Base fetcher interface for distribution security advisories."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from datetime import date
from typing import Optional

import requests

from ..models import CVERecord, DistroAdvisory

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_USER_AGENT = "linux-kernel-patch-tracker/1.0 (+https://github.com/kernel-patch-tracker)"


class BaseFetcher(ABC):
    """Abstract base class for advisory fetchers."""

    def __init__(self, name: str, params: dict):
        self.name = name
        self.params = params
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def _get(self, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        for attempt in range(DEFAULT_RETRIES):
            try:
                resp = self.session.get(url, **kwargs)
                if resp.status_code == 200:
                    return resp
                elif resp.status_code == 404:
                    logger.debug("%s: 404 for %s", self.name, url)
                    return None
                else:
                    logger.warning(
                        "%s: HTTP %d for %s", self.name, resp.status_code, url
                    )
            except requests.RequestException as e:
                logger.warning("%s: attempt %d failed for %s: %s", self.name, attempt + 1, url, e)
                time.sleep(2 ** attempt)
        return None

    @abstractmethod
    def fetch_recent_cves(self, lookback_days: int = 30) -> list[str]:
        """Return list of CVE IDs seen in the recent period."""
        ...

    @abstractmethod
    def get_advisory(self, cve_id: str) -> Optional[DistroAdvisory]:
        """Get advisory details for a specific CVE."""
        ...
