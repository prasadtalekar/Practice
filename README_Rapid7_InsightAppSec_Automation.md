# Rapid7 InsightAppSec Monthly Scan Automation

This repository includes a standard-library Python automation utility for
monthly Rapid7 InsightAppSec scan cycles across a large application inventory.
It is designed for cron, Jenkins, GitHub Actions, or another enterprise
scheduler.

## What the automation does

1. Reads a CSV inventory of InsightAppSec applications and scan configurations.
2. Creates a monthly cycle plan that spreads applications across daily batches.
3. Starts only the due scans for the current schedule window.
4. Updates the cycle tracker with Rapid7 scan IDs and scan statuses.
5. Produces a Markdown report showing coverage, exceptions, and business unit
   summaries.

This approach avoids launching all ~400 scans at once and gives each monthly
cycle an auditable tracking file.

## Files

- `automation/rapid7_insightappsec_monthly.py` - CLI automation tool.
- `templates/rapid7_inventory_template.csv` - inventory template.
- `templates/rapid7_automation_config.example.json` - API/runtime settings.

## Prerequisites

- Python 3.8 or newer.
- Rapid7 Insight platform API key with InsightAppSec permissions.
- Existing InsightAppSec application IDs and scan configuration IDs.

Export the API key before launching or monitoring scans:

```bash
export RAPID7_INSIGHT_API_KEY="your-api-key"
```

For non-US Rapid7 regions, update `api_base_url` in a copied config file.

## 1. Build the application inventory

Copy the template and replace the placeholder rows with the real application
list:

```bash
cp templates/rapid7_inventory_template.csv rapid7_inventory.csv
```

Required columns:

- `app_name`
- `app_id`
- `scan_config_id`

Recommended tracking columns:

- `owner`
- `business_unit`
- `criticality`
- `region`
- `scan_window_utc`
- `active`
- `notes`

Set `active` to `yes` for applications that should be included in the monthly
cycle. Use `no` for applications that are temporarily out of scope.

## 2. Create a monthly scan plan

Example for 400 applications, 20 applications per business day:

```bash
python3 automation/rapid7_insightappsec_monthly.py plan \
  --inventory rapid7_inventory.csv \
  --output cycles/2026-05.csv \
  --cycle-id 2026-05 \
  --start-date 2026-05-18 \
  --apps-per-day 20
```

The output cycle CSV becomes the monthly source of truth. Each row tracks:

- batch number
- scheduled date
- scan status
- Rapid7 scan ID
- launch/completion timestamps
- failure reason

## 3. Dry-run the launch batch

Always dry-run before starting scans:

```bash
python3 automation/rapid7_insightappsec_monthly.py launch \
  --cycle-file cycles/2026-05.csv \
  --config rapid7_automation_config.json \
  --date 2026-05-18 \
  --max-starts 20 \
  --dry-run
```

## 4. Launch due scans

```bash
python3 automation/rapid7_insightappsec_monthly.py launch \
  --cycle-file cycles/2026-05.csv \
  --config rapid7_automation_config.json \
  --date 2026-05-18 \
  --max-starts 20
```

Recommended scheduler pattern:

- Run `launch` every 15-30 minutes during approved scan windows.
- Keep `max_starts_per_run` conservative, such as 15-25, until scan engine
  capacity is confirmed.
- Use `scan_window_utc` to prevent scans from starting outside approved windows.

## 5. Monitor scan status

Run the monitor command periodically while scans are active:

```bash
python3 automation/rapid7_insightappsec_monthly.py monitor \
  --cycle-file cycles/2026-05.csv \
  --config rapid7_automation_config.json
```

Suggested scheduler frequency: every 30-60 minutes during the scan cycle.

## 6. Retry failed starts or failed scans

After investigating the cause, mark failed rows for rerun:

```bash
python3 automation/rapid7_insightappsec_monthly.py retry-failed \
  --cycle-file cycles/2026-05.csv
```

Then run `launch` again for the same cycle file.

## 7. Generate the monthly report

```bash
python3 automation/rapid7_insightappsec_monthly.py report \
  --cycle-file cycles/2026-05.csv \
  --output reports/2026-05-rapid7-scan-cycle.md
```

The report includes:

- total applications in scope
- completed scan percentage
- status counts
- completion by business unit
- exceptions requiring action

## Recommended operating model for ~400 apps

- Keep one inventory row per InsightAppSec scan configuration.
- Start with 20 applications per business day and adjust after observing scan
  duration and scan engine utilization.
- Prioritize `critical` and `high` applications early in the month.
- Reserve the final batch days for retries, authentication failures, WAF
  tuning, and owner follow-up.
- Treat the generated cycle CSV and Markdown report as monthly audit evidence.

## Example cron entries

```cron
# Launch due scans during an approved UTC window.
*/30 1-7 * * 1-5 cd /path/to/repo && /usr/bin/python3 automation/rapid7_insightappsec_monthly.py launch --cycle-file cycles/$(date +\%Y-\%m).csv --config rapid7_automation_config.json

# Refresh scan statuses.
15 * * * 1-5 cd /path/to/repo && /usr/bin/python3 automation/rapid7_insightappsec_monthly.py monitor --cycle-file cycles/$(date +\%Y-\%m).csv --config rapid7_automation_config.json
```

