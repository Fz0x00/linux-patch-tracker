"""Delay analyzer: compute patch latency for each CVE × distro."""

from __future__ import annotations

import logging
from datetime import date
from typing import Optional

from .models import (
    CVERecord,
    DistroAdvisory,
    DistroStatus,
    LatencyRecord,
    AlertLevel,
)

logger = logging.getLogger(__name__)


class LatencyAnalyzer:
    """Compute delay between upstream stable fix and distro fix."""

    def __init__(self, warning_threshold: int = 14, critical_threshold: int = 30):
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold

    def compute_latency(
        self,
        cve: CVERecord,
        advisory: DistroAdvisory,
    ) -> LatencyRecord:
        """Compute a single latency record.

        Args:
            cve: CVE record with upstream fix info.
            advisory: Distro advisory for this CVE.

        Returns:
            LatencyRecord with computed delay and alert level.
        """
        record = LatencyRecord(
            cve_id=cve.cve_id,
            distro_name=advisory.distro_name,
            upstream_fix_date=cve.upstream_fix_date,
            distro_fix_date=advisory.fix_date,
            status=advisory.status,
            kernel_version=advisory.kernel_version,
            advisory_id=advisory.advisory_id,
            advisory_url=advisory.advisory_url,
            source=advisory.source_url,
        )

        if advisory.status == DistroStatus.NOT_AFFECTED:
            record.delay_days = 0
            record.alert_level = AlertLevel.NONE
        elif advisory.status == DistroStatus.PENDING:
            if cve.upstream_fix_date:
                days_since = (date.today() - cve.upstream_fix_date).days
                record.delay_days = days_since
                record.alert_level = (
                    AlertLevel.CRITICAL
                    if days_since > self.critical_threshold
                    else AlertLevel.WARNING
                    if days_since > self.warning_threshold
                    else AlertLevel.INFO
                )
            else:
                record.delay_days = None
                record.alert_level = AlertLevel.INFO
        elif advisory.status == DistroStatus.FIXED:
            if advisory.fix_date and cve.upstream_fix_date:
                record.delay_days = (advisory.fix_date - cve.upstream_fix_date).days
            elif advisory.fix_date is None:
                record.delay_days = None
            else:
                record.delay_days = None

            if record.delay_days is not None:
                if record.delay_days > self.critical_threshold:
                    record.alert_level = AlertLevel.CRITICAL
                elif record.delay_days > self.warning_threshold:
                    record.alert_level = AlertLevel.WARNING
                elif record.delay_days < 0:
                    record.alert_level = AlertLevel.NONE
                else:
                    record.alert_level = AlertLevel.NONE
            else:
                record.alert_level = AlertLevel.INFO
        else:
            record.alert_level = AlertLevel.INFO

        return record

    def compute_all(
        self,
        cves: list[CVERecord],
        advisories_by_cve: dict[str, list[DistroAdvisory]],
    ) -> list[LatencyRecord]:
        """Compute latency for all CVE × distro combinations.

        Args:
            cves: List of CVE records.
            advisories_by_cve: Mapping of CVE ID to list of advisories.

        Returns:
            List of latency records.
        """
        records = []
        for cve in cves:
            advisories = advisories_by_cve.get(cve.cve_id, [])
            for adv in advisories:
                record = self.compute_latency(cve, adv)
                records.append(record)

        return records

    @staticmethod
    def group_by_cve(records: list[LatencyRecord]) -> dict[str, list[LatencyRecord]]:
        """Group records by CVE ID."""
        grouped = {}
        for r in records:
            grouped.setdefault(r.cve_id, []).append(r)
        return grouped

    @staticmethod
    def get_slowest_distros(records: list[LatencyRecord], top_n: int = 5) -> list[LatencyRecord]:
        """Return the N slowest distros across all CVEs."""
        delayed = [r for r in records if r.delay_days is not None and r.delay_days > 0]
        delayed.sort(key=lambda r: r.delay_days, reverse=True)
        return delayed[:top_n]

    @staticmethod
    def get_fastest_distros(records: list[LatencyRecord], top_n: int = 5) -> list[LatencyRecord]:
        """Return the N fastest distros (negative delay = ahead of upstream)."""
        fast = [r for r in records if r.delay_days is not None and r.delay_days < 0]
        fast.sort(key=lambda r: r.delay_days)
        return fast[:top_n]
