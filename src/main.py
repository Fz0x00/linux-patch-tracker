"""Main entry point for the kernel patch tracker."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import date, datetime
from pathlib import Path

import yaml

from .models import CVERecord, DistroAdvisory, DistroStatus, LatencyRecord
from .sources.kernel_org import fetch_stable_releases, get_upstream_fix_date
from .sources.rhel import RHELFetcher
from .sources.aws import AWSFetcher
from .sources.ubuntu import UbuntuFetcher
from .sources.aliyun import AliyunFetcher
from .sources.oracle import OracleFetcher
from .sources.debian import DebianFetcher
from .sources.azure import AzureFetcher
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
    "azure": AzureFetcher,
}


def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def collect_cves(config: dict) -> set[str]:
    """Collect CVE IDs from all enabled distro sources."""
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

        if fetcher_name == "azure":
            continue

        fetcher = fetcher_cls(distro["name"], distro.get("params", {}))
        try:
            cves = fetcher.fetch_recent_cves(lookback)
            all_cves.update(cves)
            logger.info("%s: found %d CVEs", distro["name"], len(cves))
        except Exception as e:
            logger.error("%s: fetch failed: %s", distro["name"], e)

    return all_cves


def resolve_upstream(cve_ids: set[str], config: dict) -> list[CVERecord]:
    """Resolve upstream fix dates for CVEs from kernel.org."""
    kernel_cfg = config.get("kernel_org", {})
    branches = kernel_cfg.get("stable_branches", [])

    stable_releases = []
    for branch in branches:
        series = branch.get("series", "")
        releases = fetch_stable_releases([series])
        stable_releases.extend(releases)

    stable_releases.sort(key=lambda r: r.release_date, reverse=True)

    cves = []
    for cve_id in sorted(cve_ids):
        fix_date, version, url = get_upstream_fix_date(cve_id, stable_releases)
        cves.append(CVERecord(
            cve_id=cve_id,
            upstream_version=version,
            upstream_fix_date=fix_date,
            upstream_changelog_url=url,
        ))
        logger.info("%s: upstream fix=%s %s", cve_id, fix_date, version)

    return cves


def collect_advisories(
    cves: list[CVERecord], config: dict
) -> dict[str, list[DistroAdvisory]]:
    """Collect advisories from all enabled distros for each CVE."""
    advisories: dict[str, list[DistroAdvisory]] = {}

    for distro in config.get("distros", []):
        if not distro.get("enabled", True):
            continue

        fetcher_name = distro["fetcher"]
        fetcher_cls = FETCHER_MAP.get(fetcher_name)
        if not fetcher_cls:
            continue

        fetcher = fetcher_cls(distro["name"], distro.get("params", {}))

        if fetcher_name == "azure":
            for cve in cves:
                info = fetcher.get_latest_kernel_info()
                adv = DistroAdvisory(
                    distro_name=distro["name"],
                    cve_id=cve.cve_id,
                    status=DistroStatus.UNKNOWN,
                    source_url=fetcher.repo_url,
                )
                if info:
                    adv.kernel_version = info.get("version", "")
                    adv.fix_date = info.get("build_date")
                advisories.setdefault(cve.cve_id, []).append(adv)
            continue

        for cve in cves:
            try:
                adv = fetcher.get_advisory(cve.cve_id)
                if adv:
                    advisories.setdefault(cve.cve_id, []).append(adv)
                    logger.info(
                        "%s → %s: %s %s",
                        cve.cve_id,
                        distro["name"],
                        adv.status.value,
                        adv.fix_date or "",
                    )
            except Exception as e:
                logger.error("%s on %s: %s", cve.cve_id, distro["name"], e)

    return advisories


def main():
    parser = argparse.ArgumentParser(description="Linux kernel patch latency tracker")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--output", default="data", help="Output directory")
    parser.add_argument("--skip-upstream", action="store_true", help="Skip upstream resolution (use cached)")
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
    logger.info("Total unique CVEs: %d", len(cve_ids))

    if args.skip_upstream and (output_dir / "cves.json").exists():
        logger.info("Loading cached CVEs")
        with open(output_dir / "cves.json") as f:
            cve_data = json.load(f)
        cves = [CVERecord(**c) for c in cve_data]
    else:
        logger.info("=== Step 2: Resolving upstream fix dates ===")
        cves = resolve_upstream(cve_ids, config)
        cve_dicts = [c.to_dict() for c in cves]
        with open(output_dir / "cves.json", "w") as f:
            json.dump(cve_dicts, f, indent=2, ensure_ascii=False)

    logger.info("=== Step 3: Collecting advisories ===")
    advisories = collect_advisories(cves, config)

    logger.info("=== Step 4: Computing latency ===")
    warning_threshold = config["settings"].get("alert_thresholds", {}).get("warning", 14)
    critical_threshold = config["settings"].get("alert_thresholds", {}).get("critical", 30)
    analyzer = LatencyAnalyzer(warning_threshold, critical_threshold)
    records = analyzer.compute_all(cves, advisories)

    logger.info("=== Step 5: Generating reports ===")
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
        logger.info("=== Step 6: Managing GitHub Issues ===")
        github_repo = os.environ.get("GITHUB_REPOSITORY")
        close_resolved_issues(records, github_repo)

        for record in records:
            if should_create_issue(record, set()):
                create_github_issue(record, github_repo)

    logger.info("=== Done ===")


if __name__ == "__main__":
    main()
