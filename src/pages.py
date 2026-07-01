"""GitHub Pages HTML dashboard generator."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Optional

from .models import LatencyRecord, CVERecord, DistroStatus, AlertLevel

logger = logging.getLogger(__name__)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux 内核补丁时效追踪</title>
    <style>
        :root {
            --bg: #0d1117;
            --card: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --green: #3fb950;
            --yellow: #d29922;
            --red: #f85149;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 24px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { font-size: 26px; margin-bottom: 6px; }
        .subtitle { color: var(--text-muted); margin-bottom: 28px; font-size: 14px; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 14px;
            margin-bottom: 36px;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }
        .stat-value { font-size: 28px; font-weight: 700; }
        .stat-label { color: var(--text-muted); font-size: 13px; }
        .stat-card.green .stat-value { color: var(--green); }
        .stat-card.yellow .stat-value { color: var(--yellow); }
        .stat-card.red .stat-value { color: var(--red); }
        .stat-card.blue .stat-value { color: var(--accent); }
        .legend {
            display: flex;
            gap: 16px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            color: var(--text-muted);
        }
        .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }
        .timeline-section { margin-bottom: 48px; }
        .cve-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap;
        }
        .cve-id { font-size: 18px; font-weight: 700; color: var(--accent); }
        .cve-severity {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }
        .sev-high { background: rgba(248,81,73,0.15); color: var(--red); }
        .sev-critical { background: rgba(248,81,73,0.25); color: #ff7b72; }
        .cve-desc { color: var(--text-muted); font-size: 13px; }
        .tl-container {
            position: relative;
            padding-left: 32px;
        }
        .tl-container::before {
            content: '';
            position: absolute;
            left: 11px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: var(--border);
        }
        .tl-item {
            position: relative;
            margin-bottom: 20px;
        }
        .tl-dot {
            position: absolute;
            left: -32px;
            top: 14px;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: 700;
            z-index: 1;
        }
        .tl-dot.upstream { background: var(--accent); color: #fff; }
        .tl-dot.fast { background: var(--green); color: #fff; }
        .tl-dot.ok { background: var(--text-muted); color: #fff; }
        .tl-dot.slow { background: var(--yellow); color: #000; }
        .tl-dot.critical { background: var(--red); color: #fff; }
        .tl-dot.pending { background: var(--yellow); color: #000; }
        .tl-content {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 18px;
        }
        .tl-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }
        .tl-distro-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            background: #21262d;
            border: 1px solid var(--border);
        }
        .tl-distro-tag .name { font-weight: 600; }
        .tl-distro-tag .delta { font-weight: 700; font-size: 11px; }
        .tl-distro-tag.fast .delta { color: var(--green); }
        .tl-distro-tag.ok .delta { color: var(--text-muted); }
        .tl-distro-tag.slow .delta { color: var(--yellow); }
        .tl-distro-tag.critical .delta { color: var(--red); }
        .tl-distro-tag.pending .delta { color: var(--yellow); font-style: italic; }
        .tl-date { font-size: 12px; color: var(--text-muted); white-space: nowrap; }
        .tl-bar-wrap {
            margin-top: 10px;
            height: 6px;
            background: #21262d;
            border-radius: 3px;
            overflow: hidden;
        }
        .tl-bar {
            height: 100%;
            border-radius: 3px;
            transition: width 0.3s;
        }
        .tl-bar.fast { background: var(--green); }
        .tl-bar.ok { background: var(--text-muted); }
        .tl-bar.slow { background: var(--yellow); }
        .tl-bar.critical { background: var(--red); }
        .tl-bar.pending { background: var(--yellow); }
        .advisory-id { font-size: 11px; color: var(--text-muted); margin-left: 6px; }
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-muted);
        }
        .empty-state h3 { font-size: 18px; margin-bottom: 8px; color: var(--text); }
        .generated {
            color: var(--text-muted);
            font-size: 12px;
            margin-top: 40px;
            text-align: center;
        }
        @media (max-width: 768px) {
            .tl-row { flex-direction: column; align-items: flex-start; }
            .tl-distro-tag { font-size: 11px; }
        }
    </style>
</head>
<body>
<div class="container">
    <h1>Linux 内核补丁时效追踪</h1>
    <p class="subtitle">监控主流公有云 Linux 发行版对上游 kernel.org 漏洞修复的响应速度</p>

    <div class="stats">
        <div class="stat-card blue"><div class="stat-value">{{ total_cves }}</div><div class="stat-label">追踪 CVE</div></div>
        <div class="stat-card green"><div class="stat-value">{{ fixed_count }}</div><div class="stat-label">已修复</div></div>
        <div class="stat-card yellow"><div class="stat-value">{{ pending_count }}</div><div class="stat-label">待修复</div></div>
        <div class="stat-card red"><div class="stat-value">{{ critical_count }}</div><div class="stat-label">严重延迟 (>30d)</div></div>
    </div>

    <div class="legend">
        <div class="legend-item"><div class="legend-dot" style="background:var(--accent)"></div>上游修复</div>
        <div class="legend-item"><div class="legend-dot" style="background:var(--green)"></div>≤7d 快速</div>
        <div class="legend-item"><div class="legend-dot" style="background:var(--text-muted)"></div>8~14d 正常</div>
        <div class="legend-item"><div class="legend-dot" style="background:var(--yellow)"></div>15~30d 偏慢</div>
        <div class="legend-item"><div class="legend-dot" style="background:var(--red)"></div>>30d 严重</div>
        <div class="legend-item"><div class="legend-dot" style="background:var(--yellow)"></div>待修复</div>
    </div>

    {% for cve in cve_list %}
    <div class="timeline-section">
        <div class="cve-header">
            <span class="cve-id">{{ cve.cve_id }}</span>
            <span class="cve-severity {% if cve.severity == 'Critical' %}sev-critical{% else %}sev-high{% endif %}">{{ cve.severity }} {{ cve.cvss_score }}</span>
            <span class="cve-desc">{{ cve.description }}</span>
        </div>
        <div class="tl-container">
            <div class="tl-item">
                <div class="tl-dot upstream">U</div>
                <div class="tl-content">
                    <div class="tl-row">
                        <div><strong>上游 kernel.org</strong> &mdash; {{ cve.upstream_version or '?' }}</div>
                        <div class="tl-date">{{ cve.upstream_fix_date or 'unknown' }}</div>
                    </div>
                </div>
            </div>
            {% for r in cve.records %}
            <div class="tl-item">
                <div class="tl-dot {{ r.tl_cls }}">{{ r.dot_label }}</div>
                <div class="tl-content">
                    <div class="tl-row">
                        <div>
                            <span class="tl-distro-tag {{ r.tl_cls }}">
                                <span class="name">{{ r.distro_name }}</span>
                                <span class="delta">{{ r.delta_text }}</span>
                            </span>
                            {% if r.advisory_id %}<span class="advisory-id">{{ r.advisory_id }}</span>{% endif %}
                        </div>
                        <div class="tl-date">{{ r.fix_date or '—' }}</div>
                    </div>
                    <div class="tl-bar-wrap">
                        <div class="tl-bar {{ r.tl_cls }}" style="width:{{ r.bar_width }}%"></div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endfor %}

    <p class="generated">Generated at {{ generated_at }} by linux-kernel-patch-tracker</p>
</div>
</body>
</html>"""


def _classify(delta: int | None) -> str:
    if delta is None:
        return "pending"
    if delta <= 7:
        return "fast"
    if delta <= 14:
        return "ok"
    if delta <= 30:
        return "slow"
    return "critical"


def _bar_width(delta: int | None) -> int:
    if delta is None:
        return 0
    return min(max(int((delta / 45) * 100), 2), 100)


def generate_dashboard_html(
    records: list[LatencyRecord],
    cves: list[CVERecord],
    generated_at: Optional[datetime] = None,
) -> str:
    """Generate timeline-style HTML dashboard for GitHub Pages."""
    if generated_at is None:
        generated_at = datetime.utcnow()

    from jinja2 import Template

    # Group records by CVE
    by_cve: dict[str, list[LatencyRecord]] = {}
    for r in records:
        by_cve.setdefault(r.cve_id, []).append(r)

    cve_list = []
    for cve in cves:
        recs = by_cve.get(cve.cve_id, [])
        # Sort: fixed first (by delta asc), then pending
        sorted_recs = sorted(
            recs,
            key=lambda r: (
                0 if r.status == DistroStatus.FIXED else 1,
                r.delay_days if r.delay_days is not None else 999,
            ),
        )
        enriched = []
        for r in sorted_recs:
            cls = "pending" if r.status == DistroStatus.PENDING else _classify(r.delay_days)
            if r.status == DistroStatus.NOT_AFFECTED:
                cls = "ok"
            if r.status == DistroStatus.UNKNOWN:
                cls = "critical"

            if r.status == DistroStatus.PENDING:
                dot = "!"
                delta_text = f"pending {'+' + str(r.delay_days) + 'd' if r.delay_days else ''}"
            elif r.delay_days is not None and r.delay_days <= 0:
                dot = str(r.delay_days)
                delta_text = f"{r.delay_days}d (fast)"
            elif r.delay_days is not None:
                dot = str(r.delay_days) if r.delay_days < 10 else "+" + str(r.delay_days)
                delta_text = f"+{r.delay_days}d"
            else:
                dot = "?"
                delta_text = r.status.value

            enriched.append({
                "distro_name": r.distro_name,
                "status": r.status.value,
                "delay_days": r.delay_days,
                "fix_date": r.distro_fix_date.strftime("%Y-%m-%d") if r.distro_fix_date else None,
                "advisory_id": r.advisory_id or "",
                "tl_cls": cls,
                "dot_label": dot,
                "delta_text": delta_text,
                "bar_width": _bar_width(r.delay_days),
            })

        cve_list.append({
            "cve_id": cve.cve_id,
            "severity": cve.severity,
            "cvss_score": cve.cvss_score,
            "description": cve.description,
            "upstream_version": cve.upstream_version,
            "upstream_fix_date": cve.upstream_fix_date.strftime("%Y-%m-%d") if cve.upstream_fix_date else None,
            "records": enriched,
        })

    fixed_count = sum(1 for r in records if r.status == DistroStatus.FIXED)
    pending_count = sum(1 for r in records if r.status == DistroStatus.PENDING)
    critical_count = sum(
        1 for r in records if r.delay_days is not None and r.delay_days > 30
    )

    template = Template(DASHBOARD_HTML)
    return template.render(
        total_cves=len(cves),
        fixed_count=fixed_count,
        pending_count=pending_count,
        critical_count=critical_count,
        cve_list=cve_list,
        generated_at=generated_at.strftime("%Y-%m-%d %H:%M UTC"),
    )
