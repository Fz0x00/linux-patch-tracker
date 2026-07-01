# linux-patch-tracker

自动追踪主流公有云 Linux 发行版对上游 kernel.org 漏洞修复的响应速度。

## 覆盖发行版

| 发行版 | 数据源 | 数据格式 |
|---|---|---|
| **kernel.org** | `cdn.kernel.org` ChangeLog | 上游 stable 基准 |
| **RHEL 8/9/10** | `access.redhat.com` REST API | JSON API |
| **AWS AL2/AL2023** | `explore.alas.aws.amazon.com` | HTML + Livepatch |
| **Ubuntu 22.04/24.04** | `ubuntu.com/security` | HTML + USN RSS |
| **Aliyun 2** | `mirrors.aliyun.com/alinux/cve/` | XML + RSS |
| **Oracle UEKR8** | `oss.oracle.com/pipermail/el-errata/` | 邮件列表 |
| **Debian trixie** | `security-tracker.debian.org` | HTML |

## 工作流

```
kernel.org ChangeLog → 提取 CVE + 上游修复日
                          ↓
各发行版公告系统 → 提取发行版修复日
                          ↓
延迟计算 Δ = 发行版修复日 − 上游修复日
                          ↓
        ┌─────────────────┼─────────────────┐
        ↓                 ↓                 ↓
   CSV 数据文件     Markdown 报告      GitHub Issues
                        ↓                 (延迟告警)
                 GitHub Pages 仪表板
```

## 本地运行

```bash
cd tracker
pip install -r requirements.txt

# 运行追踪
python -m src.main --config config.yaml --output data

# 查看报告
cat data/report.md

# 查看仪表板
open data/index.html
```

## GitHub Actions

项目配置了每日定时运行（UTC 06:00）：

1. **数据采集**：从所有数据源抓取最新 CVE 和公告
2. **延迟计算**：计算每个 CVE × 发行版的 Δ 延迟
3. **报告生成**：输出 CSV、Markdown 报告、HTML 仪表板
4. **自动提交**：将数据变更提交到仓库
5. **GitHub Pages**：自动部署仪表板到 gh-pages
6. **Issue 告警**：对严重延迟（>30 天）创建 Issue，补丁发布后自动关闭

### 手动触发

在仓库的 Actions 页面选择 "Daily Patch Tracking" → Run workflow。

## 配置

编辑 `config.yaml`：

```yaml
settings:
  lookback_days: 30          # 回溯天数
  min_cvss: 5.0             # 最低追踪的 CVSS
  alert_thresholds:
    warning: 14              # > 14 天创建 warning Issue
    critical: 30             # > 30 天创建 critical Issue
```

## 输出文件

| 文件 | 说明 |
|---|---|
| `data/latency.csv` | 延迟矩阵 CSV |
| `data/report.md` | Markdown 格式的完整报告 |
| `data/index.html` | GitHub Pages 仪表板 |

## 技术架构

```
src/
├── models.py          # 数据模型（CVE、Advisory、LatencyRecord）
├── analyzer.py        # 延迟计算引擎
├── report.py          # Markdown + CSV 报告生成
├── pages.py           # HTML 仪表板（Jinja2 模板）
├── issue.py           # GitHub Issue 自动创建/关闭
├── main.py            # 入口
└── sources/
    ├── base.py        # BaseFetcher 抽象类
    ├── kernel_org.py  # 上游 kernel.org 追踪
    ├── rhel.py        # RHEL JSON API
    ├── aws.py         # AWS ALAS explore 页
    ├── ubuntu.py      # Ubuntu CVE + USN
    ├── aliyun.py      # Aliyun XML + RSS
    ├── oracle.py      # Oracle el-errata 邮件列表
    └── debian.py      # Debian security tracker
```

## 扩展新数据源

1. 在 `src/sources/` 下创建新 fetcher，继承 `BaseFetcher`
2. 实现 `fetch_recent_cves()` 和 `get_advisory()`
3. 在 `FETCHER_MAP` 中注册
4. 在 `config.yaml` 中添加配置

## License

MIT
