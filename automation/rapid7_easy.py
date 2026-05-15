#!/usr/bin/env python3
"""Beginner-friendly wrapper for monthly Rapid7 InsightAppSec automation.

Use this script when you want the simplest workflow with default file names:

    python3 automation/rapid7_easy.py setup
    python3 automation/rapid7_easy.py plan --start-date 2026-05-18
    python3 automation/rapid7_easy.py dry-run-today
    python3 automation/rapid7_easy.py start-today
    python3 automation/rapid7_easy.py status
    python3 automation/rapid7_easy.py report
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import sys
from pathlib import Path
from typing import Optional, Sequence

from rapid7_insightappsec_monthly import (
    AutomationError,
    create_plan,
    default_cycle_id,
    generate_report,
    launch_scans,
    mark_failed_for_retry,
    monitor_scans,
    parse_date,
    utc_now,
    validate_cycle,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = Path("rapid7_inventory.csv")
DEFAULT_CONFIG = Path("rapid7_automation_config.json")
DEFAULT_APPS_PER_DAY = 20


def current_cycle_id() -> str:
    return default_cycle_id(utc_now().date())


def default_cycle_file(cycle_id: Optional[str] = None) -> Path:
    return Path("cycles") / f"{cycle_id or current_cycle_id()}.csv"


def default_report_file(cycle_id: Optional[str] = None) -> Path:
    cycle = cycle_id or current_cycle_id()
    return Path("reports") / f"{cycle}-rapid7-scan-cycle.md"


def copy_if_missing(source: Path, destination: Path, force: bool) -> None:
    if destination.exists() and not force:
        print(f"Keeping existing {destination}")
        return
    shutil.copyfile(source, destination)
    print(f"Created {destination}")


def setup_defaults(force: bool) -> None:
    copy_if_missing(
        REPO_ROOT / "templates" / "rapid7_inventory_template.csv",
        DEFAULT_INVENTORY,
        force,
    )
    copy_if_missing(
        REPO_ROOT / "templates" / "rapid7_automation_config.example.json",
        DEFAULT_CONFIG,
        force,
    )
    print("")
    print("Next steps:")
    print(f"1. Edit {DEFAULT_INVENTORY} and paste your real app list.")
    print('2. Export your API key: export RAPID7_INSIGHT_API_KEY="your-api-key"')
    print("3. Create the monthly plan:")
    print("   python3 automation/rapid7_easy.py plan --start-date YYYY-MM-DD")


def require_cycle_file(path: Path) -> None:
    if not path.exists():
        raise AutomationError(
            f"Missing {path}. Run this first: "
            "python3 automation/rapid7_easy.py plan --start-date YYYY-MM-DD"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Simple Rapid7 InsightAppSec monthly scan commands."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup = subparsers.add_parser("setup", help="Create the default inventory/config files.")
    setup.add_argument("--force", action="store_true", help="Overwrite existing defaults.")

    plan = subparsers.add_parser("plan", help="Create this month's scan plan.")
    plan.add_argument("--start-date", required=True, help="First scan date, YYYY-MM-DD.")
    plan.add_argument("--cycle-id", default=current_cycle_id(), help="Month label, e.g. 2026-05.")
    plan.add_argument("--apps-per-day", type=int, default=DEFAULT_APPS_PER_DAY)
    plan.add_argument("--include-weekends", action="store_true")

    dry_run = subparsers.add_parser(
        "dry-run-today", help="Show which scans would start today."
    )
    dry_run.add_argument("--cycle-id", default=current_cycle_id())
    dry_run.add_argument("--max-starts", type=int)

    start = subparsers.add_parser("start-today", help="Start due scans for today.")
    start.add_argument("--cycle-id", default=current_cycle_id())
    start.add_argument("--max-starts", type=int)

    status = subparsers.add_parser("status", help="Refresh Rapid7 scan statuses.")
    status.add_argument("--cycle-id", default=current_cycle_id())

    retry = subparsers.add_parser("retry-failed", help="Mark failed scans for another try.")
    retry.add_argument("--cycle-id", default=current_cycle_id())

    report = subparsers.add_parser("report", help="Create the monthly Markdown report.")
    report.add_argument("--cycle-id", default=current_cycle_id())

    check = subparsers.add_parser("check-plan", help="Validate the current cycle file.")
    check.add_argument("--cycle-id", default=current_cycle_id())

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "setup":
            setup_defaults(force=args.force)
        elif args.command == "plan":
            cycle_file = default_cycle_file(args.cycle_id)
            create_plan(
                inventory_path=DEFAULT_INVENTORY,
                output_path=cycle_file,
                cycle_id=args.cycle_id,
                start_date=parse_date(args.start_date),
                apps_per_day=args.apps_per_day,
                include_weekends=args.include_weekends,
            )
            print("")
            print("Next safe check:")
            print("python3 automation/rapid7_easy.py dry-run-today")
        elif args.command == "dry-run-today":
            cycle_file = default_cycle_file(args.cycle_id)
            require_cycle_file(cycle_file)
            launch_scans(
                cycle_path=cycle_file,
                config_path=DEFAULT_CONFIG,
                launch_date=dt.date.today(),
                max_starts=args.max_starts,
                dry_run=True,
            )
        elif args.command == "start-today":
            cycle_file = default_cycle_file(args.cycle_id)
            require_cycle_file(cycle_file)
            launch_scans(
                cycle_path=cycle_file,
                config_path=DEFAULT_CONFIG,
                launch_date=dt.date.today(),
                max_starts=args.max_starts,
                dry_run=False,
            )
        elif args.command == "status":
            cycle_file = default_cycle_file(args.cycle_id)
            require_cycle_file(cycle_file)
            monitor_scans(
                cycle_path=cycle_file,
                config_path=DEFAULT_CONFIG,
                dry_run=False,
            )
        elif args.command == "retry-failed":
            cycle_file = default_cycle_file(args.cycle_id)
            require_cycle_file(cycle_file)
            mark_failed_for_retry(cycle_path=cycle_file)
        elif args.command == "report":
            cycle_file = default_cycle_file(args.cycle_id)
            require_cycle_file(cycle_file)
            generate_report(
                cycle_path=cycle_file,
                output_path=default_report_file(args.cycle_id),
            )
        elif args.command == "check-plan":
            cycle_file = default_cycle_file(args.cycle_id)
            require_cycle_file(cycle_file)
            validate_cycle(cycle_path=cycle_file)
        else:
            parser.error(f"Unsupported command: {args.command}")
    except AutomationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
