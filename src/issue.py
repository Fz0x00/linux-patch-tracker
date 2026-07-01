"""GitHub Issue creator for critical patch delays."""

from __future__ import annotations

import logging
import os
from typing import Optional

from .models import LatencyRecord, DistroStatus, AlertLevel

logger = logging.getLogger(__name__)


def should_create_issue(record: LatencyRecord, existing_cves: set[str]) -> bool:
    """Check if an issue should be created for this record.

    Creates issues for:
    - Critical delays (> 30 days, pending)
    - Warning delays (> 14 days, pending) for kernel CVEs
    """
    if record.cve_id in existing_cves:
        return False
    if record.status == DistroStatus.PENDING:
        if record.alert_level == AlertLevel.CRITICAL:
            return True
        if record.alert_level == AlertLevel.WARNING:
            return True
    return False


def create_issue_body(record: LatencyRecord) -> str:
    """Generate the markdown body for a GitHub issue."""
    emoji = "red_circle" if record.alert_level == AlertLevel.CRITICAL else "yellow_circle"

    body = f"""## {record.cve_id} — {record.distro_name}

:{"{"}{emoji}:{"}"} **{record.alert_level.value.upper()}** — 补丁延迟 {record.delay_days} 天

### 详情

| 字段 | 值 |
|---|---|
| **CVE** | {record.cve_id} |
| **发行版** | {record.distro_name} |
| **状态** | {record.status.value} |
| **上游修复日** | {record.upstream_fix_date or '未知'} |
| **发行版修复日** | {record.distro_fix_date or '未发布'} |
| **延迟天数** | **{record.delay_days} 天** |
| **内核版本** | {record.kernel_version or '—'} |
| **Advisory** | {f"[{record.advisory_id}]({record.advisory_url})" if record.advisory_url else '—'} |

### 来源

{record.source}

### 建议操作

1. 检查该 CVE 是否影响你的工作负载
2. 如果影响，考虑临时缓解措施（modprobe 黑名单、sysctl 参数等）
3. 关注发行版公告等待补丁发布
4. 对于不可重启的实例，确认 kpatch/livepatch 可用性

---

*此 Issue 由 linux-kernel-patch-tracker 自动创建。当补丁发布后会自动关闭。*
"""
    return body


def create_issue_title(record: LatencyRecord) -> str:
    """Generate issue title."""
    return f"[{record.alert_level.value.upper()}] {record.cve_id} on {record.distro_name} — {record.delay_days}d delay"


def create_github_issue(
    record: LatencyRecord,
    repo: Optional[str] = None,
    token: Optional[str] = None,
) -> bool:
    """Create a GitHub issue via gh CLI or API.

    Returns True if created successfully.
    """
    title = create_issue_title(record)
    body = create_issue_body(record)

    gh_token = token or os.environ.get("GITHUB_TOKEN", "")
    if not gh_token:
        logger.warning("GITHUB_TOKEN not set, skipping issue creation")
        return False

    import subprocess

    try:
        cmd = [
            "gh", "issue", "create",
            "--title", title,
            "--body", body,
            "--label", f"alert-{record.alert_level.value}",
            "--label", "auto-generated",
        ]
        if repo:
            cmd.extend(["--repo", repo])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.info("Created issue for %s on %s: %s", record.cve_id, record.distro_name, result.stdout.strip())
            return True
        else:
            logger.error("gh issue create failed: %s", result.stderr)
            return False
    except FileNotFoundError:
        logger.error("gh CLI not found")
        return False
    except subprocess.TimeoutExpired:
        logger.error("gh issue create timed out")
        return False


def close_resolved_issues(
    records: list[LatencyRecord],
    repo: Optional[str] = None,
) -> int:
    """Close issues for CVEs that are now fixed.

    Returns count of closed issues.
    """
    import subprocess

    try:
        cmd = ["gh", "issue", "list", "--label", "auto-generated", "--state", "open", "--json", "number,title"]
        if repo:
            cmd.extend(["--repo", repo])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return 0

        import json
        issues = json.loads(result.stdout)
        closed = 0

        fixed_keys = {
            (r.cve_id, r.distro_name)
            for r in records
            if r.status == DistroStatus.FIXED
        }

        for issue in issues:
            title = issue.get("title", "")
            for cve_id, distro in fixed_keys:
                if cve_id in title and distro in title:
                    close_cmd = ["gh", "issue", "close", str(issue["number"]), "--comment", f"已修复: {cve_id} on {distro}"]
                    if repo:
                        close_cmd.extend(["--repo", repo])
                    subprocess.run(close_cmd, capture_output=True, timeout=30)
                    closed += 1
                    break

        return closed
    except Exception as e:
        logger.error("close_resolved_issues failed: %s", e)
        return 0
