"""Command line interface for LogAn."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import tracemalloc
from datetime import datetime
from pathlib import Path

import yaml

from .analyzer import (
    DEFAULT_KEYWORDS,
    VERSION,
    analyze_log_chain,
    classify_ips,
    export_json,
    generate_html_report,
)


def setup_logging(level: str = "INFO", quiet: bool = False, log_file: str | None = None) -> None:
    """Configure console and optional file logging."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = []

    console = logging.StreamHandler()
    console.setLevel(logging.WARNING if quiet else log_level)
    handlers.append(console)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        handlers.append(file_handler)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S")
    for handler in handlers:
        handler.setFormatter(formatter)

    logging.basicConfig(level=logging.DEBUG, handlers=handlers, force=True)


def load_config(config_path: str | os.PathLike[str]) -> dict:
    """Load YAML or JSON configuration."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"配置文件不存在: {path}")

    with open(path, "r", encoding="utf-8") as handle:
        if path.suffix.lower() in {".yaml", ".yml"}:
            return yaml.safe_load(handle) or {}
        if path.suffix.lower() == ".json":
            return json.load(handle)
    raise ValueError("配置文件只支持 .yaml、.yml 或 .json")


def timestamped_path(output_dir: str, base_name: str, suffix: str) -> str:
    """Build a timestamped report path."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return str(Path(output_dir) / f"{base_name}_{timestamp}.{suffix}")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logan",
        description=f"LogAn SSH 登录失败日志分析工具 v{VERSION}",
    )
    parser.add_argument("log_file", help="要分析的日志文件路径")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="异常阈值，默认 5")
    parser.add_argument("-f", "--format", choices=["html", "json", "both"], default="html", help="输出格式")
    parser.add_argument("-o", "--output", help="完整输出路径；仅输出 html 时使用 .html，json 使用 .json")
    parser.add_argument("--output-dir", default="./reports", help="自动生成报告时使用的输出目录")
    parser.add_argument("--base-name", default="report", help="自动生成报告时使用的基础文件名")
    parser.add_argument("--encoding", default="utf-8", help="日志文件编码")
    parser.add_argument("-c", "--config", help="配置文件路径，支持 YAML/JSON")
    parser.add_argument("-q", "--quiet", action="store_true", help="静默模式，只输出 warning 及以上日志")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO", help="日志级别")
    parser.add_argument("--log-file", help="程序运行日志写入文件")
    parser.add_argument("--version", action="version", version=f"LogAn {VERSION}")
    return parser


def merge_config(args: argparse.Namespace, parser: argparse.ArgumentParser, config: dict) -> argparse.Namespace:
    """Apply config values only when the CLI value is still the parser default."""
    defaults = {
        action.dest: action.default
        for action in parser._actions
        if action.dest != "help" and action.default is not argparse.SUPPRESS
    }
    for key, value in config.items():
        if hasattr(args, key) and getattr(args, key) == defaults.get(key):
            setattr(args, key, value)
    return args


def resolve_output_paths(args: argparse.Namespace) -> tuple[str | None, str | None]:
    """Resolve HTML and JSON output paths."""
    if args.output:
        output = Path(args.output)
        if args.format == "html":
            return str(output), None
        if args.format == "json":
            return None, str(output)
        if output.suffix.lower() == ".html":
            return str(output), str(output.with_suffix(".json"))
        if output.suffix.lower() == ".json":
            return str(output.with_suffix(".html")), str(output)
        return str(output.with_suffix(".html")), str(output.with_suffix(".json"))

    html_path = timestamped_path(args.output_dir, args.base_name, "html")
    json_path = timestamped_path(args.output_dir, args.base_name, "json")
    if args.format == "html":
        return html_path, None
    if args.format == "json":
        return None, json_path
    return html_path, json_path


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    config: dict = {}
    if args.config:
        config = load_config(args.config)
        args = merge_config(args, parser, config)

    setup_logging(args.log_level, args.quiet, args.log_file)

    log_file = Path(args.log_file)
    if not log_file.exists():
        logging.error("日志文件不存在: %s", log_file)
        return 1

    whitelist = config.get("whitelist", [])
    keywords = tuple(config.get("keywords", DEFAULT_KEYWORDS))
    html_path, json_path = resolve_output_paths(args)

    logging.info("LogAn v%s 启动", VERSION)
    logging.info("日志文件: %s", log_file)
    logging.info("异常阈值: %s", args.threshold)

    tracemalloc.start()
    start_time = time.time()

    try:
        ip_count, total_lines = analyze_log_chain(
            log_file,
            encoding=args.encoding,
            whitelist=whitelist,
            keywords=keywords,
        )
        normal, anomaly = classify_ips(ip_count, args.threshold)

        elapsed = time.time() - start_time
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        memory_peak_mb = peak / (1024 * 1024)

        logging.info("涉及 IP 数量: %s", len(ip_count))
        logging.info("异常 IP 数量: %s", len(anomaly))

        if html_path:
            generate_html_report(normal, anomaly, ip_count, args.threshold, str(log_file), html_path, elapsed, memory_peak_mb, total_lines)
        if json_path:
            export_json(ip_count, normal, anomaly, elapsed, memory_peak_mb, total_lines, args.threshold, json_path)

        logging.info("分析完成")
        return 0
    except KeyboardInterrupt:
        logging.warning("用户中断")
        return 130
    except Exception as exc:
        logging.error("处理失败: %s", exc, exc_info=args.log_level == "DEBUG")
        return 1


if __name__ == "__main__":
    sys.exit(main())
