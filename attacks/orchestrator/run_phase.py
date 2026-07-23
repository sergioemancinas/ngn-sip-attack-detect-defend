"""Phase runner CLI: executes every shell script in `attacks/0{phase}_*/` in name order.

Each script inherits TARGET_HOST / TARGET_PORT / OUTPUT_DIR / CLICKHOUSE_* env vars and
is responsible for invoking the attack tool, writing a PCAP, and calling the
label_emitter so each attack lands a row in ngn_sip.attack_labels.

Usage:
    python -m attacks.orchestrator.run_phase --phase 1
    python -m attacks.orchestrator.run_phase --phase 2 --target-host 127.0.0.1 --dry-run
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import click
import structlog

logger = structlog.get_logger(__name__)

PHASE_DIRS = {
    1: "01_recon",
    2: "02_credentials",
    3: "03_injection",
    4: "04_dos",
    5: "05_media",
    6: "06_tollfraud",
}


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--phase", type=int, required=True, help="Phase number 1..6")
@click.option("--target-host", default="127.0.0.1", show_default=True)
@click.option("--target-port", default=5060, show_default=True, type=int)
@click.option(
    "--output-dir",
    default="./data/pcaps",
    show_default=True,
    type=click.Path(file_okay=False),
)
@click.option(
    "--attacks-root",
    default="./attacks",
    show_default=True,
    type=click.Path(exists=True, file_okay=False),
)
@click.option("--dry-run", is_flag=True, help="List scripts and exit without executing")
def main(
    phase: int,
    target_host: str,
    target_port: int,
    output_dir: str,
    attacks_root: str,
    dry_run: bool,
) -> None:
    """Run every attack script in the named phase directory."""
    if phase not in PHASE_DIRS:
        click.echo(f"unknown phase {phase}; valid: {sorted(PHASE_DIRS)}", err=True)
        sys.exit(2)

    phase_dir = Path(attacks_root) / PHASE_DIRS[phase]
    if not phase_dir.is_dir():
        click.echo(f"phase directory not found: {phase_dir}", err=True)
        sys.exit(2)

    scripts = sorted(p for p in phase_dir.glob("*.sh") if p.is_file())
    if not scripts:
        click.echo(f"no scripts in {phase_dir}", err=True)
        sys.exit(0)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    log_path = (
        Path(output_dir)
        / f"run_phase_{phase}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.log"
    )

    env = os.environ.copy()
    env.update(
        {
            "TARGET_HOST": target_host,
            "TARGET_PORT": str(target_port),
            "OUTPUT_DIR": str(Path(output_dir).resolve()),
        }
    )

    failures: list[tuple[Path, int]] = []
    with log_path.open("w", encoding="utf-8") as logf:
        for script in scripts:
            click.echo(f"==> {script}")
            logf.write(f"\n===== {script} =====\n")
            logf.flush()
            if dry_run:
                continue
            result = subprocess.run(
                ["/bin/bash", str(script)],
                env=env,
                check=False,
                stdout=logf,
                stderr=subprocess.STDOUT,
            )
            if result.returncode != 0:
                failures.append((script, result.returncode))
                logger.warning(
                    "script_failed",
                    script=str(script),
                    returncode=result.returncode,
                )

    click.echo(f"log: {log_path}")
    if failures:
        for script, rc in failures:
            click.echo(f"FAILED rc={rc}: {script}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
