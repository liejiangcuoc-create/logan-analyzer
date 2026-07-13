from pathlib import Path

from logan.analyzer import (
    analyze_log_chain,
    build_top5,
    classify_ips,
    extract_ip,
    filter_failed,
)


def test_extract_ip_standard_line():
    line = "Failed password for root from 192.168.1.100 port 22"
    assert extract_ip(line) == "192.168.1.100"


def test_extract_ip_rejects_invalid_ipv4():
    line = "Failed password for root from 999.168.1.100 port 22"
    assert extract_ip(line) is None


def test_filter_failed_uses_default_keywords():
    lines = [
        (1, "Accepted password for alice from 192.168.1.50"),
        (2, "Failed password for root from 192.168.1.100"),
        (3, "authentication failure; rhost=203.0.113.8 user=root"),
    ]
    assert list(filter_failed(lines)) == lines[1:]


def test_classify_ips_splits_by_threshold():
    normal, anomaly = classify_ips({"1.1.1.1": 2, "2.2.2.2": 5}, threshold=5)
    assert normal == [{"ip": "1.1.1.1", "count": 2}]
    assert anomaly == [{"ip": "2.2.2.2", "count": 5}]


def test_build_top5_only_returns_five():
    anomaly = [{"ip": f"10.0.0.{index}", "count": 10 - index} for index in range(8)]
    assert len(build_top5(anomaly)) == 5


def test_analyze_log_chain_with_whitelist(tmp_path: Path):
    log_file = tmp_path / "sample.log"
    log_file.write_text(
        "\n".join(
            [
                "Failed password for root from 192.168.1.100 port 22",
                "Failed password for root from 192.168.1.100 port 22",
                "Failed password for admin from 10.0.0.55 port 22",
                "Accepted password for bob from 192.168.1.60 port 22",
            ]
        ),
        encoding="utf-8",
    )

    ip_count, total = analyze_log_chain(log_file, whitelist=["10.0.0.55"])

    assert total == 2
    assert ip_count == {"192.168.1.100": 2}
