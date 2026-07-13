import json
from pathlib import Path

from logan.analyzer import (
    analyze_log_chain,
    build_top5,
    build_top5_rows,
    classify_ips,
    count_ips,
    extract_ip,
    extract_ips,
    filter_failed,
    filter_whitelist,
    generate_html_report,
    export_json,
    lines_from_file,
)


class TestExtractIP:
    def test_standard_ip(self):
        line = "Failed password for root from 192.168.1.100 port 22"
        assert extract_ip(line) == "192.168.1.100"

    def test_authentication_failure_ip(self):
        line = "authentication failure; rhost=10.0.0.55 user=root"
        assert extract_ip(line) == "10.0.0.55"

    def test_no_ip(self):
        assert extract_ip("Accepted password for alice") is None

    def test_empty_line(self):
        assert extract_ip("") is None

    def test_multiple_ips(self):
        line = "Failed password from 192.168.1.100 via 10.0.0.1"
        assert extract_ip(line) == "192.168.1.100"

    def test_invalid_ip_format_matches_regex(self):
        line = "Failed password from 999.999.999.999"
        assert extract_ip(line) == "999.999.999.999"


class TestClassifyIPs:
    def test_normal_classification(self):
        ip_count = {"192.168.1.100": 8, "10.0.0.55": 3, "172.16.0.88": 1}
        normal, anomaly = classify_ips(ip_count, threshold=5)
        assert len(anomaly) == 1
        assert anomaly[0]["ip"] == "192.168.1.100"
        assert len(normal) == 2

    def test_all_anomaly(self):
        normal, anomaly = classify_ips({"192.168.1.1": 10, "192.168.1.2": 7}, threshold=5)
        assert normal == []
        assert [item["count"] for item in anomaly] == [10, 7]

    def test_all_normal(self):
        normal, anomaly = classify_ips({"10.0.0.1": 2, "10.0.0.2": 3}, threshold=5)
        assert len(normal) == 2
        assert anomaly == []

    def test_empty_ip_count(self):
        normal, anomaly = classify_ips({}, threshold=5)
        assert normal == []
        assert anomaly == []


class TestBuildTop5:
    def test_top5_with_anomaly(self):
        anomaly = [
            {"ip": "192.168.1.100", "count": 10},
            {"ip": "10.0.0.55", "count": 7},
            {"ip": "172.16.0.88", "count": 5},
            {"ip": "192.168.1.50", "count": 4},
            {"ip": "10.0.0.1", "count": 3},
        ]
        result = build_top5_rows(anomaly)
        for item in anomaly:
            assert item["ip"] in result

    def test_top5_less_than_5(self):
        result = build_top5_rows([{"ip": "192.168.1.100", "count": 10}])
        assert "192.168.1.100" in result

    def test_top5_empty(self):
        assert "无异常 IP" in build_top5_rows([])

    def test_build_top5_limit(self):
        anomaly = [{"ip": f"10.0.0.{index}", "count": 20 - index} for index in range(8)]
        assert len(build_top5(anomaly)) == 5


class TestGeneratorChain:
    def test_lines_from_file(self, tmp_path: Path):
        log_file = tmp_path / "sample.log"
        log_file.write_text("line1\nline2\n", encoding="utf-8")
        assert list(lines_from_file(log_file)) == [(1, "line1\n"), (2, "line2\n")]

    def test_filter_failed(self):
        lines = [
            (1, "Accepted password for alice from 192.168.1.50"),
            (2, "Failed password for root from 192.168.1.100"),
            (3, "authentication failure; rhost=203.0.113.8 user=root"),
        ]
        assert list(filter_failed(lines)) == lines[1:]

    def test_filter_with_custom_keywords(self):
        lines = [(1, "Invalid user admin from 10.0.0.55")]
        assert list(filter_failed(lines, keywords=["Invalid user"])) == lines

    def test_extract_ips(self):
        failed = [(1, "Failed password from 192.168.1.100"), (2, "no ip here")]
        assert list(extract_ips(failed)) == ["192.168.1.100"]

    def test_filter_whitelist(self):
        assert list(filter_whitelist(["1.1.1.1", "2.2.2.2"], ["1.1.1.1"])) == ["2.2.2.2"]

    def test_count_ips(self):
        assert count_ips(["1.1.1.1", "1.1.1.1", "2.2.2.2"]) == ({"1.1.1.1": 2, "2.2.2.2": 1}, 3)

    def test_analyze_log_chain(self, tmp_path: Path):
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


class TestReportExport:
    def test_generate_html_report(self, tmp_path: Path):
        output = tmp_path / "nested" / "report.html"
        ip_count = {"192.168.1.100": 8, "10.0.0.55": 2}
        normal, anomaly = classify_ips(ip_count, threshold=5)

        generate_html_report(
            normal,
            anomaly,
            ip_count,
            threshold=5,
            log_file="sample.log",
            output_path=output,
            elapsed_time=0.12,
            memory_peak=0.5,
            total_lines=10,
        )

        html = output.read_text(encoding="utf-8")
        assert "192.168.1.100" in html
        assert "LogAn" in html

    def test_generate_html_report_empty(self, tmp_path: Path):
        output = tmp_path / "report.html"
        generate_html_report([], [], {}, 5, "sample.log", output, 0, 0, 0)
        assert "无异常 IP" in output.read_text(encoding="utf-8")

    def test_export_json(self, tmp_path: Path):
        output = tmp_path / "nested" / "report.json"
        ip_count = {"192.168.1.100": 8, "10.0.0.55": 2}
        normal, anomaly = classify_ips(ip_count, threshold=5)

        export_json(ip_count, normal, anomaly, 0.12, 0.5, 10, 5, output)

        data = json.loads(output.read_text(encoding="utf-8"))
        assert data["total_failures"] == 10
        assert data["top5_anomaly_ips"][0]["ip"] == "192.168.1.100"
