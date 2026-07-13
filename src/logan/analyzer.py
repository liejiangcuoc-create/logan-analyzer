"""Core log analysis utilities for LogAn."""

from __future__ import annotations

import html
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

VERSION = "2.0.0"
DEFAULT_KEYWORDS = ("Failed password", "authentication failure", "Invalid user")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ip(line: str) -> str | None:
    """Extract the first valid IPv4 address from one log line."""
    if not line:
        return None

    match = IP_PATTERN.search(line)
    return match.group(0) if match else None


def lines_from_file(filepath: str | os.PathLike[str], encoding: str = "utf-8") -> Iterator[tuple[int, str]]:
    """Stream a text file line by line."""
    with open(filepath, "r", encoding=encoding, errors="ignore") as handle:
        for line_num, line in enumerate(handle, 1):
            if line_num % 1_000_000 == 0:
                logging.info("已读取 %s 行", f"{line_num:,}")
            yield line_num, line


def filter_failed(
    lines_iter: Iterable[tuple[int, str]],
    keywords: Iterable[str] | None = None,
) -> Iterator[tuple[int, str]]:
    """Keep only log lines containing failed-login keywords."""
    active_keywords = tuple(keywords or DEFAULT_KEYWORDS)
    for line_num, line in lines_iter:
        if any(keyword in line for keyword in active_keywords):
            yield line_num, line.rstrip("\n")


def extract_ips(failed_iter: Iterable[tuple[int, str]]) -> Iterator[str]:
    """Extract IP addresses from failed-login lines."""
    for line_num, line in failed_iter:
        ip = extract_ip(line)
        if ip:
            yield ip
        else:
            logging.debug("第 %s 行未找到有效 IP，已跳过", line_num)


def filter_whitelist(ip_iter: Iterable[str], whitelist: Iterable[str] | None = None) -> Iterator[str]:
    """Remove trusted IP addresses from the stream."""
    trusted = set(whitelist or [])
    for ip in ip_iter:
        if ip in trusted:
            logging.debug("白名单 IP 已跳过: %s", ip)
            continue
        yield ip


def count_ips(ip_iter: Iterable[str]) -> tuple[dict[str, int], int]:
    """Count login failures by IP address."""
    ip_count: dict[str, int] = {}
    total = 0
    for ip in ip_iter:
        total += 1
        ip_count[ip] = ip_count.get(ip, 0) + 1
    return ip_count, total


def analyze_log_chain(
    filepath: str | os.PathLike[str],
    encoding: str = "utf-8",
    whitelist: Iterable[str] | None = None,
    keywords: Iterable[str] | None = None,
) -> tuple[dict[str, int], int]:
    """Analyze a log file with a streaming generator chain."""
    logging.info("启动分析链: read -> filter -> extract -> whitelist -> count")
    all_lines = lines_from_file(filepath, encoding)
    failed_lines = filter_failed(all_lines, keywords)
    ips = extract_ips(failed_lines)
    filtered_ips = filter_whitelist(ips, whitelist)
    ip_count, total = count_ips(filtered_ips)
    logging.info("共处理 %s 条有效失败记录", f"{total:,}")
    return ip_count, total


def classify_ips(ip_count: dict[str, int], threshold: int = 5) -> tuple[list[dict[str, int | str]], list[dict[str, int | str]]]:
    """Split IPs into normal and anomaly lists."""
    normal: list[dict[str, int | str]] = []
    anomaly: list[dict[str, int | str]] = []

    for ip, count in ip_count.items():
        item = {"ip": ip, "count": count}
        if count >= threshold:
            anomaly.append(item)
        else:
            normal.append(item)

    normal.sort(key=lambda item: int(item["count"]), reverse=True)
    anomaly.sort(key=lambda item: int(item["count"]), reverse=True)
    return normal, anomaly


def build_top5(anomaly: list[dict[str, int | str]]) -> list[dict[str, int | str]]:
    """Return the top five anomaly IPs."""
    return anomaly[:5]


def _table_rows(ip_list: list[dict[str, int | str]], status: str, css_class: str) -> str:
    if not ip_list:
        return '<tr><td colspan="4" class="empty">无数据</td></tr>'

    rows = []
    for index, item in enumerate(ip_list, 1):
        rows.append(
            f'<tr class="{css_class}">'
            f"<td>{index}</td>"
            f"<td>{html.escape(str(item['ip']))}</td>"
            f"<td>{item['count']}</td>"
            f"<td>{html.escape(status)}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _top5_rows(anomaly: list[dict[str, int | str]]) -> str:
    top5 = build_top5(anomaly)
    if not top5:
        return '<tr><td colspan="3" class="empty">无异常 IP</td></tr>'

    rows = []
    for rank, item in enumerate(top5, 1):
        rows.append(
            "<tr>"
            f"<td>{rank}</td>"
            f"<td>{html.escape(str(item['ip']))}</td>"
            f"<td>{item['count']}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def build_top5_rows(anomaly: list[dict[str, int | str]]) -> str:
    """Return HTML table rows for the top five anomaly IPs."""
    return _top5_rows(anomaly)


def ensure_dir(filepath: str | os.PathLike[str]) -> None:
    """Create the parent directory for a file path."""
    parent = Path(filepath).expanduser().resolve().parent
    parent.mkdir(parents=True, exist_ok=True)


REPORT_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LogAn 登录失败分析报告</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #172033; }}
    h1 {{ margin-bottom: 8px; }}
    h2 {{ margin-top: 28px; }}
    .meta, .summary {{ background: #f4f7fb; border: 1px solid #dbe4f0; border-radius: 8px; padding: 14px 16px; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 960px; margin-top: 12px; }}
    th, td {{ border: 1px solid #d8dee9; padding: 8px 10px; text-align: left; }}
    th {{ background: #1f4f8f; color: white; }}
    .anomaly {{ background: #fff1f1; color: #9b1c1c; font-weight: 600; }}
    .normal {{ background: #ffffff; }}
    .empty {{ text-align: center; color: #6b7280; }}
    footer {{ margin-top: 32px; color: #667085; font-size: 14px; }}
  </style>
</head>
<body>
  <h1>LogAn 登录失败分析报告</h1>
  <p>生成时间：{generated_time}</p>

  <section class="meta">
    <strong>性能信息</strong><br>
    处理耗时：{elapsed_time:.3f} 秒 |
    峰值内存：{memory_peak:.2f} MB |
    有效失败记录：{total_failures:,} 条 |
    阈值：{threshold}
  </section>

  <h2>Top 5 危险 IP</h2>
  <table>
    <tr><th>排名</th><th>IP 地址</th><th>失败次数</th></tr>
    {top5_rows}
  </table>

  <h2>统计摘要</h2>
  <section class="summary">
    涉及 IP 数量：{total_ips} 个<br>
    异常 IP 数量：{anomaly_count} 个<br>
    扫描日志：{log_file}
  </section>

  <h2>异常 IP 列表</h2>
  <table>
    <tr><th>序号</th><th>IP 地址</th><th>失败次数</th><th>状态</th></tr>
    {anomaly_rows}
  </table>

  <h2>正常 IP 列表</h2>
  <table>
    <tr><th>序号</th><th>IP 地址</th><th>失败次数</th><th>状态</th></tr>
    {normal_rows}
  </table>

  <footer>由 LogAn v{version} 自动生成</footer>
</body>
</html>
"""


def generate_html_report(
    normal: list[dict[str, int | str]],
    anomaly: list[dict[str, int | str]],
    ip_count: dict[str, int],
    threshold: int,
    log_file: str,
    output_path: str | os.PathLike[str],
    elapsed_time: float,
    memory_peak: float,
    total_lines: int,
) -> None:
    """Write an HTML report."""
    ensure_dir(output_path)
    content = REPORT_TEMPLATE.format(
        version=VERSION,
        generated_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        elapsed_time=elapsed_time,
        memory_peak=memory_peak,
        total_lines=total_lines,
        threshold=threshold,
        top5_rows=_top5_rows(anomaly),
        total_failures=sum(ip_count.values()),
        total_ips=len(ip_count),
        anomaly_count=len(anomaly),
        anomaly_rows=_table_rows(anomaly, "异常", "anomaly"),
        normal_rows=_table_rows(normal, "正常", "normal"),
        log_file=html.escape(str(log_file)),
    )
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(content)
    logging.info("HTML 报告已生成: %s", output_path)


def export_json(
    ip_count: dict[str, int],
    normal: list[dict[str, int | str]],
    anomaly: list[dict[str, int | str]],
    elapsed_time: float,
    memory_peak: float,
    total_lines: int,
    threshold: int,
    output_path: str | os.PathLike[str],
) -> None:
    """Write a JSON report."""
    ensure_dir(output_path)
    data = {
        "version": VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "elapsed_seconds": round(elapsed_time, 3),
        "memory_peak_mb": round(memory_peak, 2),
        "total_lines_processed": total_lines,
        "threshold": threshold,
        "total_failures": sum(ip_count.values()),
        "total_ips": len(ip_count),
        "anomaly_count": len(anomaly),
        "top5_anomaly_ips": build_top5(anomaly),
        "anomaly_ips": anomaly,
        "normal_ips": normal,
        "all_ips": [{"ip": ip, "count": count} for ip, count in sorted(ip_count.items())],
    }
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    logging.info("JSON 报告已生成: %s", output_path)
