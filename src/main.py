"""Main entry point for the kernel patch latency tracker."""

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime
from pathlib import Path

import yaml

from .models import CVERecord, DistroAdvisory, DistroStatus, LatencyRecord
from .sources.rhel import RHELFetcher
from .sources.aws import AWSFetcher
from .sources.ubuntu import UbuntuFetcher
from .sources.aliyun import AliyunFetcher
from .sources.oracle import OracleFetcher
from .sources.debian import DebianFetcher
from .analyzer import LatencyAnalyzer
from .report import generate_csv, generate_markdown_report
from .pages import generate_dashboard_html
from .issue import should_create_issue, create_github_issue, close_resolved_issues

logger = logging.getLogger(__name__)

FETCHER_MAP = {
    "rhel": RHELFetcher,
    "aws": AWSFetcher,
    "ubuntu": UbuntuFetcher,
    "aliyun": AliyunFetcher,
    "oracle": OracleFetcher,
    "debian": DebianFetcher,
}


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def collect_cves(config: dict) -> list[str]:
    """Collect CVE IDs from all enabled distro sources.

    Returns sorted list, limited to MAX_CVES to avoid excessive API calls.
    """
    MAX_CVES = 100
    lookback = config["settings"].get("lookback_days", 30)
    all_cves = set()

    for distro in config.get("distros", []):
        if not distro.get("enabled", True):
            continue

        fetcher_name = distro["fetcher"]
        fetcher_cls = FETCHER_MAP.get(fetcher_name)
        if not fetcher_cls:
            logger.warning("Unknown fetcher: %s", fetcher_name)
            continue

        fetcher = fetcher_cls(distro["name"], distro.get("params", {}))
        try:
            cves = fetcher.fetch_recent_cves(lookback)
            all_cves.update(cves)
            logger.info("%s: found %d kernel CVEs", distro["name"], len(cves))
        except Exception as e:
            logger.error("%s: fetch failed: %s", distro["name"], e)

    # Sort by CVE ID descending (newest first) and limit
    sorted_cves = sorted(all_cves, reverse=True)[:MAX_CVES]
    logger.info("Total unique kernel CVEs: %d (limited to %d)", len(all_cves), len(sorted_cves))
    return sorted_cves


def collect_advisories(
    cve_ids: list[str], config: dict
) -> tuple[list[CVERecord], dict[str, list[DistroAdvisory]]]:
    """Collect advisories from all enabled distros for each CVE."""
    advisories: dict[str, list[DistroAdvisory]] = {}
    cve_record_map: dict[str, CVERecord] = {}

    for distro in config.get("distros", []):
        if not distro.get("enabled", True):
            continue

        fetcher_name = distro["fetcher"]
        fetcher_cls = FETCHER_MAP.get(fetcher_name)
        if not fetcher_cls:
            continue

        fetcher = fetcher_cls(distro["name"], distro.get("params", {}))

        for cve_id in cve_ids:
            try:
                adv = fetcher.get_advisory(cve_id)
                if adv:
                    advisories.setdefault(cve_id, []).append(adv)
                    logger.info(
                        "%s → %s: %s %s",
                        cve_id,
                        distro["name"],
                        adv.status.value,
                        adv.fix_date or "",
                    )
            except Exception as e:
                logger.error("%s on %s: %s", cve_id, distro["name"], e)

    # Build CVERecord list from advisories (only CVEs that have at least one distro entry)
    for cve_id in sorted(advisories.keys()):
        cve_record_map[cve_id] = CVERecord(cve_id=cve_id)

    return list(cve_record_map.values()), advisories


def main():
    parser = argparse.ArgumentParser(description="Linux kernel patch latency tracker")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--output", default="data", help="Output directory")
    parser.add_argument("--no-issues", action="store_true", help="Skip GitHub issue creation")
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    config = load_config(args.config)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=== Step 1: Collecting CVEs ===")
    cve_ids = collect_cves(config)
    logger.info("Total unique kernel CVEs: %d", len(cve_ids))

    logger.info("=== Step 2: Collecting advisories ===")
    cves, advisories = collect_advisories(cve_ids, config)
    logger.info("CVEs with distro data: %d", len(cves))

    logger.info("=== Step 3: Computing latency ===")
    warning_threshold = config["settings"].get("alert_thresholds", {}).get("warning", 14)
    critical_threshold = config["settings"].get("alert_thresholds", {}).get("critical", 30)
    analyzer = LatencyAnalyzer(warning_threshold, critical_threshold)
    records = analyzer.compute_all(cves, advisories)

    logger.info("=== Step 4: Generating reports ===")
    csv_data = generate_csv(records)
    with open(output_dir / "latency.csv", "w") as f:
        f.write(csv_data)

    report_md = generate_markdown_report(records, cves)
    report_path = output_dir / "report.md"
    with open(report_path, "w") as f:
        f.write(report_md)
    logger.info("Report written to %s", report_path)

    dashboard_html = generate_dashboard_html(records, cves)
    dashboard_path = output_dir / "index.html"
    with open(dashboard_path, "w") as f:
        f.write(dashboard_html)
    logger.info("Dashboard written to %s", dashboard_path)

    if not args.no_issues:
        logger.info("=== Step 5: Managing GitHub Issues ===")
        github_repo = os.environ.get("GITHUB_REPOSITORY")
        close_resolved_issues(records, github_repo)

        for record in records:
            if should_create_issue(record, set()):
                create_github_issue(record, github_repo)

    logger.info("=== Done ===")


if __name__ == "__main__":
    main()
