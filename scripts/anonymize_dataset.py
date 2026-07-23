from __future__ import annotations

"""Dataset anonymization entry point for future PCAP and CSV publishing."""

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Anonymize NGN SIP dataset artifacts.")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raise SystemExit(f"implementation pending: {args.input} -> {args.output}")


if __name__ == "__main__":
    raise SystemExit(main())
