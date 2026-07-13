from pathlib import Path
from types import SimpleNamespace

import pytest

import logan.cli as cli
from logan.cli import load_config, main, resolve_output_paths


class TestCLI:
    def test_setup_logging_with_file(self, tmp_path: Path):
        log_file = tmp_path / "logs" / "logan.log"
        cli.setup_logging("DEBUG", quiet=True, log_file=str(log_file))
        assert log_file.parent.exists()

    def test_load_config_yaml(self, tmp_path: Path):
        config = tmp_path / "config.yaml"
        config.write_text("threshold: 8\nformat: both\n", encoding="utf-8")
        assert load_config(config)["threshold"] == 8

    def test_load_config_json(self, tmp_path: Path):
        config = tmp_path / "config.json"
        config.write_text('{"threshold": 9}', encoding="utf-8")
        assert load_config(config)["threshold"] == 9

    def test_load_config_missing(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "missing.yaml")

    def test_load_config_invalid_suffix(self, tmp_path: Path):
        config = tmp_path / "config.txt"
        config.write_text("threshold=8", encoding="utf-8")
        with pytest.raises(ValueError):
            load_config(config)

    def test_timestamped_path(self, tmp_path: Path):
        path = cli.timestamped_path(str(tmp_path), "daily", "html")
        assert path.endswith(".html")
        assert Path(path).parent == tmp_path

    def test_create_parser(self):
        args = cli.create_parser().parse_args(["sample.log", "-t", "10", "-f", "json"])
        assert args.log_file == "sample.log"
        assert args.threshold == 10
        assert args.format == "json"

    def test_merge_config_keeps_cli_value(self):
        parser = cli.create_parser()
        args = parser.parse_args(["sample.log", "-t", "10"])
        merged = cli.merge_config(args, parser, {"threshold": 8, "format": "both"})
        assert merged.threshold == 10
        assert merged.format == "both"

    def test_main_generates_json(self, tmp_path: Path):
        log_file = tmp_path / "sample.log"
        output_file = tmp_path / "report.json"
        log_file.write_text("Failed password for root from 192.168.1.100 port 22\n", encoding="utf-8")

        code = main([str(log_file), "-f", "json", "-o", str(output_file)])

        assert code == 0
        assert output_file.exists()

    def test_main_generates_html_with_config(self, tmp_path: Path):
        log_file = tmp_path / "sample.log"
        output_file = tmp_path / "report.html"
        config_file = tmp_path / "config.yaml"
        log_file.write_text("Failed password for root from 192.168.1.100 port 22\n", encoding="utf-8")
        config_file.write_text("threshold: 1\nkeywords:\n  - Failed password\n", encoding="utf-8")

        code = main([str(log_file), "-f", "html", "-o", str(output_file), "-c", str(config_file)])

        assert code == 0
        assert output_file.exists()

    def test_main_missing_log_returns_error(self, tmp_path: Path):
        missing = tmp_path / "missing.log"
        assert main([str(missing)]) == 1

    def test_main_keyboard_interrupt(self, tmp_path: Path, monkeypatch):
        log_file = tmp_path / "sample.log"
        log_file.write_text("Failed password for root from 192.168.1.100 port 22\n", encoding="utf-8")

        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "analyze_log_chain", interrupt)
        assert main([str(log_file)]) == 130

    def test_main_exception(self, tmp_path: Path, monkeypatch):
        log_file = tmp_path / "sample.log"
        log_file.write_text("Failed password for root from 192.168.1.100 port 22\n", encoding="utf-8")

        def fail(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(cli, "analyze_log_chain", fail)
        assert main([str(log_file), "--log-level", "DEBUG"]) == 1

    def test_resolve_output_paths_for_html(self, tmp_path: Path):
        args = SimpleNamespace(output=str(tmp_path / "report.html"), format="html", output_dir=str(tmp_path), base_name="report")
        html_path, json_path = resolve_output_paths(args)
        assert html_path.endswith("report.html")
        assert json_path is None

    def test_resolve_output_paths_for_json(self, tmp_path: Path):
        args = SimpleNamespace(output=str(tmp_path / "report.json"), format="json", output_dir=str(tmp_path), base_name="report")
        html_path, json_path = resolve_output_paths(args)
        assert html_path is None
        assert json_path.endswith("report.json")

    def test_resolve_output_paths_for_both(self, tmp_path: Path):
        args = SimpleNamespace(
            output=str(tmp_path / "report.html"),
            format="both",
            output_dir=str(tmp_path),
            base_name="report",
        )

        html_path, json_path = resolve_output_paths(args)
        assert html_path.endswith("report.html")
        assert json_path.endswith("report.json")

    def test_resolve_output_paths_for_json_suffix_both(self, tmp_path: Path):
        args = SimpleNamespace(output=str(tmp_path / "report.json"), format="both", output_dir=str(tmp_path), base_name="report")
        html_path, json_path = resolve_output_paths(args)
        assert html_path.endswith("report.html")
        assert json_path.endswith("report.json")

    def test_resolve_output_paths_auto(self, tmp_path: Path):
        args = SimpleNamespace(output=None, format="both", output_dir=str(tmp_path), base_name="daily")
        html_path, json_path = resolve_output_paths(args)
        assert html_path.endswith(".html")
        assert json_path.endswith(".json")
