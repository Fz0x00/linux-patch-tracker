"""SQLite cache for kernel.org CVE-to-version mappings.

First run: queries NVD API with rate limiting, stores results.
Subsequent runs: queries local SQLite (instant).
The DB file is committed to the repo so Actions runs are fast.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from datetime import date
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

DB_PATH = Path("data/kernel_cves.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_upstream (
    cve_id TEXT PRIMARY KEY,
    upstream_version TEXT,
    published_date TEXT,
    fix_version TEXT,
    source TEXT DEFAULT 'nvd',
    fetched_at TEXT
);

CREATE TABLE IF NOT EXISTS fetch_log (
    id INTEGER PRIMARY KEY,
    fetched_at TEXT,
    cve_count INTEGER,
    source TEXT
);
"""


def get_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(SCHEMA)
    return conn


def lookup_cve(conn: sqlite3.Connection, cve_id: str) -> Optional[dict]:
    """Look up upstream fix info from cache.

    Returns {upstream_version, published_date, fix_version} or None.
    """
    row = conn.execute(
        "SELECT upstream_version, published_date, fix_version FROM cve_upstream WHERE cve_id = ?",
        (cve_id,),
    ).fetchone()
    if row:
        pub = None
        if row[1]:
            try:
                pub = date.fromisoformat(row[1])
            except Exception:
                pass
        return {"upstream_version": row[0] or "", "published_date": pub, "fix_version": row[2] or ""}
    return None


def _query_nvd_batch(cve_ids: list[str], rate_limit: float = 6.0) -> list[dict]:
    """Query NVD API for a batch of CVEs with rate limiting.

    NVD without API key: 5 requests per 30 seconds = 1 per 6 seconds.
    Returns list of {cve_id, published, fix_version}.
    """
    results = []
    for i, cve_id in enumerate(cve_ids):
        if i > 0:
            time.sleep(rate_limit)
        try:
            resp = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                timeout=15,
            )
            if not resp.ok:
                logger.warning("NVD %s: HTTP %d", cve_id, resp.status_code)
                continue

            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                continue

            cve_data = vulns[0].get("cve", {})
            pub_str = cve_data.get("published", "")
            fix_ver = ""

            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable") is False:
                            parts = match.get("criteria", "").split(":")
                            if len(parts) >= 6 and "linux" in parts[3]:
                                fix_ver = parts[5]

            # Parse published date
            pub_date = ""
            if pub_str:
                try:
                    from dateutil import parser as dp
                    pub_date = dp.parse(pub_str).date().isoformat()
                except Exception:
                    pub_date = pub_str[:10]

            results.append({
                "cve_id": cve_id,
                "published": pub_date,
                "fix_version": fix_ver,
            })
            logger.info("NVD %s: published=%s fix=%s", cve_id, pub_date, fix_ver)

        except Exception as e:
            logger.warning("NVD %s: %s", cve_id, e)

    return results


def fetch_and_cache(cve_ids: set[str], conn: sqlite3.Connection, rate_limit: float = 6.0) -> int:
    """Fetch upstream info from NVD for CVEs not already cached.

    Returns number of newly cached CVEs.
    """
    # Find which CVEs we still need
    uncached = []
    for cve_id in sorted(cve_ids):
        existing = conn.execute(
            "SELECT 1 FROM cve_upstream WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if not existing:
            uncached.append(cve_id)

    if not uncached:
        logger.info("All %d CVEs already cached", len(cve_ids))
        return 0

    logger.info("Fetching %d CVEs from NVD (uncached)...", len(uncached))
    results = _query_nvd_batch(uncached, rate_limit)

    now = date.today().isoformat()
    for r in results:
        conn.execute(
            """INSERT OR REPLACE INTO cve_upstream
               (cve_id, upstream_version, published_date, fix_version, source, fetched_at)
               VALUES (?, ?, ?, ?, 'nvd', ?)""",
            (r["cve_id"], r["fix_version"], r["published"], r["fix_version"], now),
        )

    conn.execute(
        "INSERT INTO fetch_log (fetched_at, cve_count, source) VALUES (?, ?, 'nvd')",
        (now, len(results)),
    )
    conn.commit()

    logger.info("Cached %d new CVE entries", len(results))
    return len(results)


def get_stats(conn: sqlite3.Connection) -> dict:
    """Get database statistics."""
    total = conn.execute("SELECT COUNT(*) FROM cve_upstream").fetchone()[0]
    return {"total_cached": total}
