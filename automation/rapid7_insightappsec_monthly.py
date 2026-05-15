#!/usr/bin/env python3
"""Monthly Rapid7 InsightAppSec scan orchestration.

This tool reads an application inventory, creates a monthly batch plan, starts
scheduled InsightAppSec scans through the API, monitors scan completion, and
generates cycle reports. It intentionally uses only the Python standard
library so it can run from cron, Jenkins, GitHub Actions, or a jump host without
extra package installation.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


ACTIVE_VALUES = {"1", "active", "true", "yes", "y"}
TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELED", "CANCELLED", "SKIPPED"}
IN_FLIGHT_STATUSES = {"LAUNCHED", "QUEUED", "RUNNING", "IN_PROGRESS"}
DEFAULT_CYCLE_FIELDS = [
    "cycle_id",
    "batch_number",
    "scheduled_date",
    "app_name",
    "app_id",
    "scan_config_id",
    "owner",
    "business_unit",
    "criticality",
    "region",
    "scan_window_utc",
    "status",
    "scan_id",
    "launched_at_utc",
    "completed_at_utc",
    "failure_reason",
    "last_checked_at_utc",
    "notes",
]
INVENTORY_REQUIRED_FIELDS = ["app_name", "app_id", "scan_config_id"]
INVENTORY_OPTIONAL_FIELDS = [
    "owner",
    "business_unit",
    "criticality",
    "region",
    "scan_window_utc",
    "active",
    "notes",
]
CRITICALITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class AutomationError(Exception):
    """Raised for expected operational failures."""


class InsightAppSecClient:
    """Small Rapid7 InsightAppSec API client."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: int = 60,
        retries: int = 3,
        retry_sleep_seconds: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.retries = retries
        self.retry_sleep_seconds = retry_sleep_seconds

    def start_scan(self, scan_config_id: str) -> Tuple[Dict[str, Any], str]:
        payload = {"scan_config": {"id": scan_config_id}}
        data, headers = self._request("POST", "/scans", payload)
        scan_id = extract_id(data, headers.get("Location"))
        return data, scan_id

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        data, _headers = self._request("GET", f"/scans/{urllib.parse.quote(scan_id)}")
        return data

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, str]]:
        url = self.base_url + path
        body = None
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Api-Key": self.api_key,
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        last_error: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            try:
                with urllib.request.urlopen(
                    request, timeout=self.timeout_seconds
                ) as response:
                    raw = response.read().decode("utf-8")
                    response_headers = dict(response.headers.items())
                    if not raw.strip():
                        return {}, response_headers
                    return json.loads(raw), response_headers
            except urllib.error.HTTPError as error:
                raw_error = error.read().decode("utf-8", errors="replace")
                if error.code < 500 or attempt == self.retries:
                    raise AutomationError(
                        f"{method} {url} failed with HTTP {error.code}: {raw_error}"
                    ) from error
                last_error = error
            except (urllib.error.URLError, TimeoutError) as error:
                last_error = error
                if attempt == self.retries:
                    break
            time.sleep(self.retry_sleep_seconds * attempt)

        raise AutomationError(f"{method} {url} failed: {last_error}")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_utc(value: Optional[dt.datetime] = None) -> str:
    timestamp = value or utc_now()
    return timestamp.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_date(value: str) -> dt.date:
    try:
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise AutomationError(f"Invalid date '{value}'. Use YYYY-MM-DD.") from error


def default_cycle_id(today: Optional[dt.date] = None) -> str:
    current = today or utc_now().date()
    return current.strftime("%Y-%m")


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise AutomationError(f"CSV file not found: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise AutomationError(f"CSV file has no header row: {path}")
        return [{key: (value or "").strip() for key, value in row.items()} for row in reader]


def write_csv(path: Path, rows: Sequence[Dict[str, str]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temp_path.replace(path)


def load_config(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise AutomationError(f"Config file not found: {path}")
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def build_client(config: Dict[str, Any]) -> InsightAppSecClient:
    api_key_env = config.get("api_key_env", "RAPID7_INSIGHT_API_KEY")
    api_key = os.environ.get(api_key_env)
    if not api_key:
        raise AutomationError(f"Missing API key. Export {api_key_env}=<Rapid7 API key>.")

    base_url = config.get("api_base_url", "https://us.api.insight.rapid7.com/ias/v1")
    return InsightAppSecClient(
        base_url=base_url,
        api_key=api_key,
        timeout_seconds=int(config.get("request_timeout_seconds", 60)),
        retries=int(config.get("retries", 3)),
        retry_sleep_seconds=int(config.get("retry_sleep_seconds", 3)),
    )


def validate_inventory(rows: Sequence[Dict[str, str]]) -> None:
    missing_fields = [field for field in INVENTORY_REQUIRED_FIELDS if field not in rows[0]]
    if missing_fields:
        raise AutomationError(
            "Inventory is missing required columns: " + ", ".join(missing_fields)
        )

    problems: List[str] = []
    seen_scan_configs = set()
    for index, row in enumerate(rows, start=2):
        app_name = row.get("app_name", "")
        for field in INVENTORY_REQUIRED_FIELDS:
            if not row.get(field):
                problems.append(f"row {index}: missing {field}")
        scan_config_id = row.get("scan_config_id", "")
        if scan_config_id and scan_config_id in seen_scan_configs:
            problems.append(f"row {index}: duplicate scan_config_id {scan_config_id}")
        seen_scan_configs.add(scan_config_id)
        if not app_name:
            problems.append(f"row {index}: app_name is empty")

    if problems:
        raise AutomationError("Inventory validation failed:\n- " + "\n- ".join(problems))


def is_active(row: Dict[str, str]) -> bool:
    value = row.get("active", "yes").strip().lower()
    return value in ACTIVE_VALUES or value == ""


def sort_inventory(rows: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    def sort_key(row: Dict[str, str]) -> Tuple[int, str, str]:
        criticality = row.get("criticality", "").strip().lower()
        business_unit = row.get("business_unit", "").strip().lower()
        app_name = row.get("app_name", "").strip().lower()
        return (CRITICALITY_ORDER.get(criticality, 4), business_unit, app_name)

    return sorted(rows, key=sort_key)


def planned_dates(
    start_date: dt.date,
    app_count: int,
    apps_per_day: int,
    include_weekends: bool,
) -> List[dt.date]:
    if apps_per_day < 1:
        raise AutomationError("--apps-per-day must be greater than zero")

    batches_needed = (app_count + apps_per_day - 1) // apps_per_day
    dates: List[dt.date] = []
    cursor = start_date
    while len(dates) < batches_needed:
        if include_weekends or cursor.weekday() < 5:
            dates.append(cursor)
        cursor += dt.timedelta(days=1)
    return dates


def create_plan(
    inventory_path: Path,
    output_path: Path,
    cycle_id: str,
    start_date: dt.date,
    apps_per_day: int,
    include_weekends: bool,
) -> None:
    inventory = read_csv(inventory_path)
    if not inventory:
        raise AutomationError("Inventory is empty.")
    validate_inventory(inventory)

    active_rows = sort_inventory(row for row in inventory if is_active(row))
    dates = planned_dates(start_date, len(active_rows), apps_per_day, include_weekends)
    planned_rows: List[Dict[str, str]] = []

    for index, row in enumerate(active_rows):
        batch_index = index // apps_per_day
        planned_rows.append(
            {
                "cycle_id": cycle_id,
                "batch_number": str(batch_index + 1),
                "scheduled_date": dates[batch_index].isoformat(),
                "app_name": row.get("app_name", ""),
                "app_id": row.get("app_id", ""),
                "scan_config_id": row.get("scan_config_id", ""),
                "owner": row.get("owner", ""),
                "business_unit": row.get("business_unit", ""),
                "criticality": row.get("criticality", ""),
                "region": row.get("region", ""),
                "scan_window_utc": row.get("scan_window_utc", ""),
                "status": "PLANNED",
                "scan_id": "",
                "launched_at_utc": "",
                "completed_at_utc": "",
                "failure_reason": "",
                "last_checked_at_utc": "",
                "notes": row.get("notes", ""),
            }
        )

    write_csv(output_path, planned_rows, DEFAULT_CYCLE_FIELDS)
    print(
        f"Created {output_path} with {len(planned_rows)} applications "
        f"across {len(dates)} batch day(s)."
    )


def within_window(scan_window_utc: str, now: Optional[dt.datetime] = None) -> bool:
    window = scan_window_utc.strip()
    if not window:
        return True
    try:
        start_raw, end_raw = window.split("-", 1)
        start_time = dt.time.fromisoformat(start_raw.strip())
        end_time = dt.time.fromisoformat(end_raw.strip())
    except ValueError:
        return True

    current = (now or utc_now()).time().replace(microsecond=0)
    if start_time <= end_time:
        return start_time <= current <= end_time
    return current >= start_time or current <= end_time


def eligible_for_launch(row: Dict[str, str], launch_date: dt.date) -> bool:
    if row.get("status") not in {"PLANNED", "RETRY"}:
        return False
    scheduled = parse_date(row.get("scheduled_date", ""))
    return scheduled <= launch_date and within_window(row.get("scan_window_utc", ""))


def extract_id(data: Dict[str, Any], location: Optional[str] = None) -> str:
    for key in ("id", "scan_id", "scanId"):
        value = data.get(key)
        if value:
            return str(value)
    nested_scan = data.get("scan")
    if isinstance(nested_scan, dict):
        for key in ("id", "scan_id", "scanId"):
            value = nested_scan.get(key)
            if value:
                return str(value)
    if location:
        return location.rstrip("/").split("/")[-1]
    return ""


def launch_scans(
    cycle_path: Path,
    config_path: Optional[Path],
    launch_date: dt.date,
    max_starts: Optional[int],
    dry_run: bool,
) -> None:
    rows = read_csv(cycle_path)
    config = load_config(config_path)
    configured_max = int(config.get("max_starts_per_run", 25))
    max_to_start = max_starts if max_starts is not None else configured_max
    candidates = [row for row in rows if eligible_for_launch(row, launch_date)]
    selected = candidates[:max_to_start]

    if dry_run:
        for row in selected:
            print(
                "DRY RUN would start "
                f"{row['app_name']} scan_config_id={row['scan_config_id']}"
            )
        print(f"DRY RUN selected {len(selected)} of {len(candidates)} eligible scan(s).")
        return

    client = build_client(config)
    delay_seconds = float(config.get("launch_delay_seconds", 0))
    launched = 0

    for row in rows:
        if row not in selected:
            continue
        try:
            _data, scan_id = client.start_scan(row["scan_config_id"])
            row["status"] = "LAUNCHED"
            row["scan_id"] = scan_id
            row["launched_at_utc"] = iso_utc()
            row["failure_reason"] = ""
            launched += 1
            print(f"Started {row['app_name']} scan_id={scan_id or 'unknown'}")
            if delay_seconds > 0:
                time.sleep(delay_seconds)
        except AutomationError as error:
            row["status"] = "FAILED"
            row["failure_reason"] = str(error)
            row["last_checked_at_utc"] = iso_utc()
            print(f"Failed to start {row['app_name']}: {error}", file=sys.stderr)

    write_csv(cycle_path, rows, DEFAULT_CYCLE_FIELDS)
    print(f"Started {launched} scan(s). Updated {cycle_path}.")


def normalize_scan_status(scan: Dict[str, Any]) -> str:
    for key in ("status", "scan_status", "scanStatus", "state"):
        value = scan.get(key)
        if isinstance(value, str) and value.strip():
            normalized = value.strip().upper().replace(" ", "_")
            if normalized in {"SUCCEEDED", "SUCCESS", "COMPLETE", "FINISHED"}:
                return "COMPLETED"
            if normalized in {"CANCELLED"}:
                return "CANCELED"
            return normalized

    scan_status = scan.get("scan")
    if isinstance(scan_status, dict):
        return normalize_scan_status(scan_status)
    return "UNKNOWN"


def extract_failure(scan: Dict[str, Any]) -> str:
    for key in ("failure_reason", "failureReason", "error", "message"):
        value = scan.get(key)
        if value:
            return str(value)
    return ""


def monitor_scans(cycle_path: Path, config_path: Optional[Path], dry_run: bool) -> None:
    rows = read_csv(cycle_path)
    to_check = [row for row in rows if row.get("status") in IN_FLIGHT_STATUSES]

    if dry_run:
        print(f"DRY RUN would check {len(to_check)} in-flight scan(s).")
        return

    config = load_config(config_path)
    client = build_client(config)
    checked = 0

    for row in rows:
        if row.get("status") not in IN_FLIGHT_STATUSES:
            continue
        scan_id = row.get("scan_id")
        if not scan_id:
            row["status"] = "FAILED"
            row["failure_reason"] = "Missing scan_id after launch."
            continue
        try:
            scan = client.get_scan(scan_id)
            status = normalize_scan_status(scan)
            row["status"] = status
            row["last_checked_at_utc"] = iso_utc()
            if status in TERMINAL_STATUSES:
                row["completed_at_utc"] = row["completed_at_utc"] or iso_utc()
            if status in {"FAILED", "ERROR"}:
                row["failure_reason"] = extract_failure(scan)
            checked += 1
            print(f"{row['app_name']} scan_id={scan_id} status={status}")
        except AutomationError as error:
            row["last_checked_at_utc"] = iso_utc()
            row["failure_reason"] = str(error)
            print(f"Failed to check {row['app_name']}: {error}", file=sys.stderr)

    write_csv(cycle_path, rows, DEFAULT_CYCLE_FIELDS)
    print(f"Checked {checked} scan(s). Updated {cycle_path}.")


def mark_failed_for_retry(cycle_path: Path) -> None:
    rows = read_csv(cycle_path)
    changed = 0
    for row in rows:
        if row.get("status") in {"FAILED", "ERROR"}:
            row["status"] = "RETRY"
            row["scan_id"] = ""
            row["launched_at_utc"] = ""
            row["completed_at_utc"] = ""
            changed += 1
    write_csv(cycle_path, rows, DEFAULT_CYCLE_FIELDS)
    print(f"Marked {changed} failed scan(s) for retry.")


def report_rows(rows: Sequence[Dict[str, str]]) -> str:
    total = len(rows)
    status_counts = Counter(row.get("status", "UNKNOWN") or "UNKNOWN" for row in rows)
    completed = status_counts.get("COMPLETED", 0)
    terminal = sum(status_counts.get(status, 0) for status in TERMINAL_STATUSES)
    coverage = (completed / total * 100) if total else 0.0
    terminal_rate = (terminal / total * 100) if total else 0.0

    lines = [
        "# Rapid7 InsightAppSec Monthly Scan Cycle Report",
        "",
        f"Generated: {iso_utc()}",
        f"Total applications: {total}",
        f"Completed scans: {completed} ({coverage:.1f}%)",
        f"Terminal scan states: {terminal} ({terminal_rate:.1f}%)",
        "",
        "## Status Summary",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status, count in sorted(status_counts.items()):
        lines.append(f"| {status} | {count} |")

    lines.extend(["", "## Business Unit Summary", "", "| Business Unit | Completed | Total |"])
    lines.append("| --- | ---: | ---: |")
    by_unit: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_unit[row.get("business_unit") or "Unassigned"].append(row)
    for unit, unit_rows in sorted(by_unit.items()):
        unit_completed = sum(1 for row in unit_rows if row.get("status") == "COMPLETED")
        lines.append(f"| {unit} | {unit_completed} | {len(unit_rows)} |")

    exceptions = [
        row
        for row in rows
        if row.get("status") in {"FAILED", "ERROR", "RETRY", "UNKNOWN"}
    ]
    lines.extend(["", "## Exceptions Requiring Action", ""])
    if not exceptions:
        lines.append("No failed, retry, or unknown scans.")
    else:
        lines.append("| Application | Owner | Status | Reason |")
        lines.append("| --- | --- | --- | --- |")
        for row in exceptions:
            reason = row.get("failure_reason", "").replace("|", "\\|")
            lines.append(
                f"| {row.get('app_name', '')} | {row.get('owner', '')} | "
                f"{row.get('status', '')} | {reason} |"
            )

    return "\n".join(lines) + "\n"


def generate_report(cycle_path: Path, output_path: Optional[Path]) -> None:
    rows = read_csv(cycle_path)
    report = report_rows(rows)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")
        print(f"Wrote report to {output_path}")
    else:
        print(report)


def validate_cycle(cycle_path: Path) -> None:
    rows = read_csv(cycle_path)
    missing = [
        field for field in DEFAULT_CYCLE_FIELDS if rows and field not in rows[0]
    ]
    if missing:
        raise AutomationError("Cycle file is missing columns: " + ", ".join(missing))
    duplicate_configs = [
        scan_config_id
        for scan_config_id, count in Counter(
            row.get("scan_config_id", "") for row in rows
        ).items()
        if scan_config_id and count > 1
    ]
    if duplicate_configs:
        raise AutomationError(
            "Cycle file has duplicate scan_config_id values: "
            + ", ".join(sorted(duplicate_configs))
        )
    print(f"Validated {cycle_path}: {len(rows)} row(s).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automate monthly Rapid7 InsightAppSec scan cycles."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="Create a monthly cycle CSV from inventory.")
    plan.add_argument("--inventory", required=True, type=Path)
    plan.add_argument("--output", required=True, type=Path)
    plan.add_argument("--cycle-id", default=default_cycle_id())
    plan.add_argument("--start-date", default=utc_now().date().isoformat())
    plan.add_argument("--apps-per-day", type=int, default=20)
    plan.add_argument("--include-weekends", action="store_true")

    launch = subparsers.add_parser("launch", help="Start due scans from a cycle CSV.")
    launch.add_argument("--cycle-file", required=True, type=Path)
    launch.add_argument("--config", type=Path)
    launch.add_argument("--date", default=utc_now().date().isoformat())
    launch.add_argument("--max-starts", type=int)
    launch.add_argument("--dry-run", action="store_true")

    monitor = subparsers.add_parser("monitor", help="Refresh scan statuses in a cycle CSV.")
    monitor.add_argument("--cycle-file", required=True, type=Path)
    monitor.add_argument("--config", type=Path)
    monitor.add_argument("--dry-run", action="store_true")

    retry = subparsers.add_parser("retry-failed", help="Mark failed scans for rerun.")
    retry.add_argument("--cycle-file", required=True, type=Path)

    report = subparsers.add_parser("report", help="Create a Markdown cycle report.")
    report.add_argument("--cycle-file", required=True, type=Path)
    report.add_argument("--output", type=Path)

    validate = subparsers.add_parser("validate-cycle", help="Validate a cycle CSV.")
    validate.add_argument("--cycle-file", required=True, type=Path)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "plan":
            create_plan(
                inventory_path=args.inventory,
                output_path=args.output,
                cycle_id=args.cycle_id,
                start_date=parse_date(args.start_date),
                apps_per_day=args.apps_per_day,
                include_weekends=args.include_weekends,
            )
        elif args.command == "launch":
            launch_scans(
                cycle_path=args.cycle_file,
                config_path=args.config,
                launch_date=parse_date(args.date),
                max_starts=args.max_starts,
                dry_run=args.dry_run,
            )
        elif args.command == "monitor":
            monitor_scans(
                cycle_path=args.cycle_file,
                config_path=args.config,
                dry_run=args.dry_run,
            )
        elif args.command == "retry-failed":
            mark_failed_for_retry(cycle_path=args.cycle_file)
        elif args.command == "report":
            generate_report(cycle_path=args.cycle_file, output_path=args.output)
        elif args.command == "validate-cycle":
            validate_cycle(cycle_path=args.cycle_file)
        else:
            parser.error(f"Unsupported command: {args.command}")
    except AutomationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
