"""GitHub Pages HTML dashboard generator."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

from jinja2 import Template
from .models import LatencyRecord, CVERecord, DistroStatus, AlertLevel

logger = logging.getLogger(__name__)

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
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
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { font-size: 28px; margin-bottom: 8px; }
        .subtitle { color: var(--text-muted); margin-bottom: 24px; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        .stat-card {
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }
        .stat-value { font-size: 32px; font-weight: 700; }
        .stat-label { color: var(--text-muted); font-size: 14px; }
        .stat-card.green .stat-value { color: var(--green); }
        .stat-card.yellow .stat-value { color: var(--yellow); }
        .stat-card.red .stat-value { color: var(--red); }
        .stat-card.blue .stat-value { color: var(--accent); }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        th, td {
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 13px;
        }
        th {
            background: #21262d;
            font-weight: 600;
            position: sticky;
            top: 0;
            white-space: nowrap;
        }
        tr:hover { background: #1c2128; }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
        }
        .badge-fixed { background: rgba(63,185,80,0.15); color: var(--green); }
        .badge-pending { background: rgba(210,153,34,0.15); color: var(--yellow); }
        .badge-na { background: rgba(139,148,158,0.15); color: var(--text-muted); }
        .badge-unknown { background: rgba(248,81,73,0.15); color: var(--red); }
        .delay-fast { color: var(--green); font-weight: 600; }
        .delay-slow { color: var(--red); font-weight: 600; }
        .delay-ok { color: var(--text-muted); }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .section { margin-bottom: 32px; }
        .section-title { font-size: 20px; margin-bottom: 12px; }
        .generated { color: var(--text-muted); font-size: 12px; margin-top: 40px; }
    </style>
</head>
<body>
<div class="container">
    <h1>Linux 内核补丁时效追踪</h1>
    <p class="subtitle">监控主流公有云 Linux 发行版对上游 kernel.org 漏洞修复的响应速度</p>

    <div class="stats">
        <div class="stat-card blue">
            <div class="stat-value">{{ total_cves }}</div>
            <div class="stat-label">追踪 CVE</div>
        </div>
        <div class="stat-card green">
            <div class="stat-value">{{ fixed_count }}</div>
            <div class="stat-label">已修复</div>
        </div>
        <div class="stat-card yellow">
            <div class="stat-value">{{ pending_count }}</div>
            <div class="stat-label">待修复</div>
        </div>
        <div class="stat-card red">
            <div class="stat-value">{{ critical_count }}</div>
            <div class="stat-label">严重延迟 (>30d)</div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">补丁延迟矩阵</h2>
        <table>
            <thead>
                <tr>
                    <th>CVE</th>
                    {% for d in distros %}
                    <th>{{ d }}</th>
                    {% endfor %}
                </tr>
            </thead>
            <tbody>
                {% for cve_id, rows in matrix.items() %}
                <tr>
                    <td><strong>{{ cve_id }}</strong></td>
                    {% for d in distros %}
                    {% set r = rows.get(d) %}
                    {% if r %}
                        <td>
                            {% if r.status == 'not_affected' %}
                                <span class="badge badge-na">N/A</span>
                            {% elif r.status == 'pending' %}
                                <span class="badge badge-pending">pending</span>
                                {% if r.delay_days %}<br><span class="delay-slow">{{ r.delay_days }}d</span>{% endif %}
                            {% elif r.status == 'fixed' %}
                                {% if r.delay_days is not none %}
                                    {% if r.delay_days < 0 %}
                                        <span class="delay-fast">{{ r.delay_days }}d</span>
                                    {% elif r.delay_days > 30 %}
                                        <span class="delay-slow">+{{ r.delay_days }}d</span>
                                    {% else %}
                                        <span class="delay-ok">+{{ r.delay_days }}d</span>
                                    {% endif %}
                                {% else %}
                                    <span class="badge badge-fixed">fixed</span>
                                {% endif %}
                            {% else %}
                                <span class="badge badge-unknown">?</span>
                            {% endif %}
                        </td>
                    {% else %}
                        <td>—</td>
                    {% endif %}
                    {% endfor %}
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    {% if slowest %}
    <div class="section">
        <h2 class="section-title">最慢响应 TOP 10</h2>
        <table>
            <thead>
                <tr><th>CVE</th><th>发行版</th><th>延迟</th><th>状态</th><th>链接</th></tr>
            </thead>
            <tbody>
                {% for r in slowest %}
                <tr>
                    <td>{{ r.cve_id }}</td>
                    <td>{{ r.distro_name }}</td>
                    <td class="delay-slow">+{{ r.delay_days }}d</td>
                    <td><span class="badge badge-{{ r.status }}">{{ r.status }}</span></td>
                    <td>{% if r.advisory_url %}<a href="{{ r.advisory_url }}">advisory</a>{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <p class="generated">Generated at {{ generated_at }} by linux-kernel-patch-tracker</p>
</div>
</body>
</html>"""


def generate_dashboard_html(
    records: list[LatencyRecord],
    cves: list[CVERecord],
    generated_at: Optional[datetime] = None,
) -> str:
    """Generate HTML dashboard for GitHub Pages."""
    if generated_at is None:
        generated_at = datetime.utcnow()

    distro_names = sorted(set(r.distro_name for r in records))
    cve_ids = sorted(set(r.cve_id for r in records))

    matrix = {}
    for cve_id in cve_ids:
        matrix[cve_id] = {}
        for d in distro_names:
            matching = [r for r in records if r.cve_id == cve_id and r.distro_name == d]
            if matching:
                r = matching[0]
                matrix[cve_id][d] = {
                    "status": r.status.value,
                    "delay_days": r.delay_days,
                }
            else:
                matrix[cve_id][d] = None

    slowest = sorted(
        [r for r in records if r.delay_days is not None and r.delay_days > 0],
        key=lambda r: r.delay_days,
        reverse=True,
    )[:10]

    fixed_count = sum(1 for r in records if r.status == DistroStatus.FIXED)
    pending_count = sum(1 for r in records if r.status == DistroStatus.PENDING)
    critical_count = sum(
        1 for r in records if r.delay_days is not None and r.delay_days > 30
    )

    template = Template(DASHBOARD_TEMPLATE)
    return template.render(
        total_cves=len(cve_ids),
        fixed_count=fixed_count,
        pending_count=pending_count,
        critical_count=critical_count,
        distros=distro_names,
        matrix=matrix,
        slowest=[
            {
                "cve_id": r.cve_id,
                "distro_name": r.distro_name,
                "delay_days": r.delay_days,
                "status": r.status.value,
                "advisory_url": r.advisory_url,
            }
            for r in slowest
        ],
        generated_at=generated_at.strftime("%Y-%m-%d %H:%M UTC"),
    )
