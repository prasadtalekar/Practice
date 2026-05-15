# Rapid7 InsightAppSec Monthly Scan Automation

This is the simple version.

The goal is:

1. Put all applications in one CSV file.
2. Split them into safe daily batches.
3. Start only today's batch.
4. Check scan status.
5. Create a monthly report.

For about 400 applications, start with **20 applications per day**. That spreads
the work across roughly one business month and avoids starting hundreds of scans
at once.

## Simple workflow

### Step 1: Create the files

Run:

```bash
python3 automation/rapid7_easy.py setup
```

This creates:

- `rapid7_inventory.csv`
- `rapid7_automation_config.json`

### Step 2: Fill in the application list

Open `rapid7_inventory.csv` and add one row per web application.

The three most important columns are:

```text
app_name,app_id,scan_config_id
```

Example:

```text
Customer Portal,12345,abcde
Partner API,67890,fghij
```

Keep `active` as `yes` for applications that should be scanned.

### Step 3: Add your Rapid7 API key

Run:

```bash
export RAPID7_INSIGHT_API_KEY="your-api-key"
```

If your Rapid7 account is not in the US region, update this value in
`rapid7_automation_config.json`:

```json
"api_base_url": "https://us.api.insight.rapid7.com/ias/v1"
```

### Step 4: Create the monthly plan

Choose the first scan date for the month:

```bash
python3 automation/rapid7_easy.py plan --start-date 2026-05-18
```

This creates a file like:

```text
cycles/2026-05.csv
```

That file is your monthly tracker.

### Step 5: Preview before launching

Run this first so you can see what would start:

```bash
python3 automation/rapid7_easy.py dry-run-today
```

This does not start any scans.

### Step 6: Start today's scans

When the preview looks correct:

```bash
python3 automation/rapid7_easy.py start-today
```

### Step 7: Check scan status

Run this during the scan cycle:

```bash
python3 automation/rapid7_easy.py status
```

### Step 8: Create the report

Run:

```bash
python3 automation/rapid7_easy.py report
```

This creates a report like:

```text
reports/2026-05-rapid7-scan-cycle.md
```

## What to run every day

After setup is complete, the normal daily process is only:

```bash
python3 automation/rapid7_easy.py dry-run-today
python3 automation/rapid7_easy.py start-today
python3 automation/rapid7_easy.py status
```

At the end of the month:

```bash
python3 automation/rapid7_easy.py report
```

## If scans fail

After fixing the reason for failure, run:

```bash
python3 automation/rapid7_easy.py retry-failed
python3 automation/rapid7_easy.py start-today
```

## Recommended settings for 400 applications

- Use `20` applications per day to start.
- Put critical and high-risk applications first in the month.
- Do not launch all 400 scans at the same time.
- Keep the final few days for retries and failed authentication scans.
- Use the generated CSV and report as audit evidence.

## Files included

- `automation/rapid7_easy.py` - simple commands for day-to-day use.
- `automation/rapid7_insightappsec_monthly.py` - advanced CLI with full options.
- `templates/rapid7_inventory_template.csv` - application inventory template.
- `templates/rapid7_automation_config.example.json` - config template.

## Optional scheduler example

Once you are comfortable running the commands manually, schedule them with cron
or Jenkins.

Example cron:

```cron
# Start due scans during an approved UTC window.
*/30 1-7 * * 1-5 cd /path/to/repo && /usr/bin/python3 automation/rapid7_easy.py start-today

# Refresh scan statuses.
15 * * * 1-5 cd /path/to/repo && /usr/bin/python3 automation/rapid7_easy.py status
```
