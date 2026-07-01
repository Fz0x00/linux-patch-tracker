"""Report generator: Markdown reports and CSV data export."""

from __future__ import annotations

import csv
import io
import logging
from datetime import date, datetime
from typing import Optional

from .models import LatencyRecord, DistroStatus, AlertLevel, CVERecord

logger = logging.getLogger(__name__)

CSV_HEADERS = [
    "cve_id",
    "distro",
    "upstream_fix_date",
    "distro_fix_date",
    "delay_days",
    "status",
    "kernel_version",
    "advisory_id",
    "advisory_url",
    "source",
]


def generate_csv(records: list[LatencyRecord]) -> str:
    """Generate CSV string from latency records."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(CSV_HEADERS)

    for r in records:
        writer.writerow([
            r.cve_id,
            r.distro_name,
            r.upstream_fix_date.isoformat() if r.upstream_fix_date else "",
            r.distro_fix_date.isoformat() if r.distro_fix_date else "",
            r.delay_days if r.delay_days is not None else "",
            r.status.value,
            r.kernel_version,
            r.advisory_id,
            r.advisory_url,
            r.source,
        ])

    return output.getvalue()


def generate_markdown_report(
    records: list[LatencyRecord],
    cves: list[CVERecord],
    generated_at: Optional[datetime] = None,
) -> str:
    """Generate a Markdown report from latency records."""
    if generated_at is None:
        generated_at = datetime.now()

    lines = [
        f"# Linux 内核补丁时效追踪报告",
        "",
        f"> 自动生成于 {generated_at.strftime('%Y-%m-%d %H:%M UTC')} | 数据源: kernel.org + 各发行版公告系统",
        "",
        "---",
        "",
    ]

    cve_ids = sorted(set(r.cve_id for r in records))
    distro_names = sorted(set(r.distro_name for r in records))

    lines.append("## 补丁延迟矩阵（相对上游 kernel.org stable）")
    lines.append("")

    header = "| CVE |"
    separator = "|---|"
    for d in distro_names:
        header += f" {d} |"
        separator += "---|"
    lines.append(header)
    lines.append(separator)

    cve_map = {c.cve_id: c for c in cves}

    for cve_id in cve_ids:
        cve_info = cve_map.get(cve_id)
        row = f"| {cve_id} |"
        for d in distro_names:
            matching = [r for r in records if r.cve_id == cve_id and r.distro_name == d]
            if not matching:
                row += " — |"
                continue

            r = matching[0]
            if r.status == DistroStatus.NOT_AFFECTED:
                cell = "N/A"
            elif r.status == DistroStatus.PENDING:
                cell = f"pending ({r.delay_days}d)" if r.delay_days is not None else "pending"
                if r.alert_level == AlertLevel.CRITICAL:
                    cell = f"**{cell}**"
            elif r.status == DistroStatus.FIXED:
                if r.delay_days is not None:
                    sign = "+" if r.delay_days >= 0 else ""
                    cell = f"{sign}{r.delay_days}d"
                    if r.delay_days > 30:
                        cell = f"**{cell}**"
                else:
                    cell = "fixed"
            else:
                cell = "?"

            row += f" {cell} |"
        lines.append(row)

    lines.append("")
    lines.append("---")
    lines.append("")

    from .analyzer import LatencyAnalyzer

    lines.append("## 最快响应")
    lines.append("")
    fastest = LatencyAnalyzer.get_fastest_distros(records, top_n=10)
    if fastest:
        lines.append("| CVE | 发行版 | Δ（天） | 内核版本 |")
        lines.append("|---|---|---|---|")
        for r in fastest:
            lines.append(f"| {r.cve_id} | {r.distro_name} | **{r.delay_days}d** | {r.kernel_version} |")
    else:
        lines.append("（无数据）")

    lines.append("")
    lines.append("## 最慢响应")
    lines.append("")
    slowest = LatencyAnalyzer.get_slowest_distros(records, top_n=10)
    if slowest:
        lines.append("| CVE | 发行版 | Δ（天） | 状态 | 告警 |")
        lines.append("|---|---|---|---|---|")
        for r in slowest:
            alert_icon = {"critical": "CRITICAL", "warning": "WARNING", "info": "", "none": ""}
            alert = alert_icon.get(r.alert_level.value, "")
            lines.append(
                f"| {r.cve_id} | {r.distro_name} | +{r.delay_days}d | {r.status.value} | {alert} |"
            )
    else:
        lines.append("（无数据）")

    lines.append("")
    lines.append("## 告警列表")
    lines.append("")

    alerts = [r for r in records if r.alert_level in (AlertLevel.CRITICAL, AlertLevel.WARNING)]
    if alerts:
        lines.append("| CVE | 发行版 | 延迟 | 告警级别 | 缓解建议 |")
        lines.append("|---|---|---|---|---|")
        for r in alerts:
            advice = ""
            if r.status == DistroStatus.PENDING:
                advice = "升级内核或使用 kpatch/livepatch"
            elif r.status == DistroStatus.FIXED:
                advice = "确认已升级到修复版本"
            lines.append(
                f"| {r.cve_id} | {r.distro_name} | {r.delay_days}d | {r.alert_level.value.upper()} | {advice} |"
            )
    else:
        lines.append("当前无告警。")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## CVE 详情")
    lines.append("")

    for cve_id in cve_ids:
        cve_info = cve_map.get(cve_id)
        if not cve_info:
            continue
        lines.append(f"### {cve_id}")
        lines.append("")
        lines.append(f"- **CVSS**: {cve_info.cvss_score} ({cve_info.severity})")
        lines.append(f"- **组件**: `{cve_info.component}`")
        if cve_info.upstream_version:
            lines.append(f"- **上游修复版本**: {cve_info.upstream_version} ({cve_info.upstream_fix_date})")
        lines.append(f"- **描述**: {cve_info.description[:200]}..." if len(cve_info.description) > 200 else f"- **描述**: {cve_info.description}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"*Generated by linux-kernel-patch-tracker at {generated_at.isoformat()}*")

    return "\n".join(lines)
