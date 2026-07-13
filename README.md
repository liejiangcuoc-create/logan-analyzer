# LogAn

LogAn 是一个轻量级 SSH 登录失败日志分析工具，用于从服务器日志中统计失败登录来源 IP，识别疑似暴力破解行为，并生成 HTML/JSON 报告。

## 功能

- 流式读取日志文件，适合处理大文件
- 识别 `Failed password`、`authentication failure`、`Invalid user` 等失败登录记录
- 按 IP 统计失败次数，并根据阈值标记异常 IP
- 支持 Top 5 危险 IP 排行
- 支持 HTML 和 JSON 两种报告格式
- 支持 YAML/JSON 配置文件
- 支持白名单 IP 和自定义关键字
- 提供 pytest 单元测试和 GitHub Actions CI

## 安装

从源码安装：

```powershell
git clone https://github.com/yourname/logan-analyzer.git
cd logan-analyzer
python -m pip install -e .
```

开发环境安装：

```powershell
python -m pip install -e ".[dev]"
```

只安装依赖：

```powershell
python -m pip install -r requirements.txt
```

## 使用

分析示例日志并生成 HTML 报告：

```powershell
logan examples/sample.log
```

同时生成 HTML 和 JSON：

```powershell
logan examples/sample.log -f both
```

指定异常阈值：

```powershell
logan examples/sample.log -t 8
```

指定输出路径：

```powershell
logan examples/sample.log -f both -o reports/security_report.html
```

使用配置文件：

```powershell
logan examples/sample.log -c config.example.yaml
```

如果没有安装为命令，也可以直接运行模块：

```powershell
python -m logan.cli examples/sample.log -f both
```

## 配置文件

参考 `config.example.yaml`：

```yaml
threshold: 8
format: both
output_dir: ./reports
base_name: daily_report
encoding: utf-8
quiet: false
log_level: INFO
log_file: ./logs/logan.log

whitelist:
  - 192.168.1.10
  - 10.0.0.1

keywords:
  - "Failed password"
  - "authentication failure"
  - "Invalid user"
```

## 生成测试日志

```powershell
python scripts/generate_test_log.py -o big.log -n 100000 -s 42
```

生成的大日志文件不会被 Git 跟踪，避免把大文件上传到 GitHub。

## 测试

```powershell
pytest
```

覆盖率测试：

```powershell
pytest --cov=logan --cov-report=html
```

## 项目结构

```text
logan-analyzer/
├── .github/workflows/ci.yml
├── examples/sample.log
├── scripts/generate_test_log.py
├── src/logan/
│   ├── __init__.py
│   ├── analyzer.py
│   └── cli.py
├── tests/test_analyzer.py
├── config.example.yaml
├── LICENSE
├── pyproject.toml
├── README.md
└── requirements.txt
```

## 发布到 GitHub

```powershell
cd "D:\python code\logan-analyzer"
git init
git add .
git commit -m "Initial release"
git branch -M main
git remote add origin https://github.com/yourname/logan-analyzer.git
git push -u origin main
```

上传前请把 `pyproject.toml` 和 README 里的 `yourname`、`Your Name`、`your-email@example.com` 改成你的 GitHub 用户名和邮箱。

## License

MIT
