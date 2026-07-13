"""Generate synthetic SSH logs for local performance testing."""

from __future__ import annotations

import argparse
import random
from datetime import datetime
from pathlib import Path


def generate_test_log(output_path: str, num_lines: int = 100_000, seed: int | None = None) -> str:
    if seed is not None:
        random.seed(seed)

    ips = [f"192.168.{network}.{host}" for network in range(1, 4) for host in range(1, 255)]
    users = ["root", "admin", "test", "oracle", "mysql", "deploy", "nginx"]
    ports = [22, 2222, 2022]
    base_time = datetime(2026, 7, 9, 0, 0, 0)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as handle:
        for index in range(num_lines):
            minute_offset = (index // 10) % 1440
            second_offset = index % 60
            dt = base_time.replace(
                hour=(minute_offset // 60) % 24,
                minute=minute_offset % 60,
                second=second_offset,
            )
            time_str = dt.strftime("%b %d %H:%M:%S")
            ip = random.choice(ips)
            user = random.choice(users)
            port = random.choice(ports)

            if random.random() < 0.1:
                line = f"{time_str} server sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port {port}\n"
            else:
                line = f"{time_str} server sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {ip} port {port}\n"
            handle.write(line)

    return str(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic SSH logs.")
    parser.add_argument("-o", "--output", default="big.log", help="Output log path")
    parser.add_argument("-n", "--lines", type=int, default=100_000, help="Number of lines")
    parser.add_argument("-s", "--seed", type=int, default=None, help="Random seed")
    args = parser.parse_args()

    output = generate_test_log(args.output, args.lines, args.seed)
    print(f"Generated {output}")


if __name__ == "__main__":
    main()
