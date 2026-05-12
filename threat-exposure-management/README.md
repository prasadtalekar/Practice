# Threat and Exposure Management in Microsoft Sentinel

This package defines a consolidated Threat and Exposure Management (TEM) view in
Log Analytics / Microsoft Sentinel. The goal is to compare risk across source
systems at the same grain: **one finding on one asset**.

## Scope

The initial consolidated view covers:

| Area | Source | Primary tables |
| --- | --- | --- |
| Workstation vulnerabilities | Microsoft Defender for Endpoint / Defender Vulnerability Management | `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB`, `DeviceInfo` |
| Server vulnerabilities | Microsoft Defender for Endpoint / Defender Vulnerability Management | `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB`, `DeviceInfo` |
| Web application vulnerabilities | Rapid7 InsightAppSec or InsightVM export | `Rapid7AppSecFindings_CL` |
| MDE recommendations | Defender Vulnerability Management | `DeviceTvmSecureConfigurationAssessment`, `DeviceTvmSecureConfigurationAssessmentKB`, `DeviceInfo` |
| Defender for Cloud recommendations | Defender for Cloud continuous export | `SecurityRecommendation` |

The normalized output is intentionally not "risk by machine" or "risk by
finding" only. Each row represents the combined context of:

```text
asset + finding + source + status + criticality + exposure + finding severity
```

This keeps the view fine-grained enough for remediation while still supporting
company-level dashboards.

## Required ingestion

### 1. Defender Vulnerability Management

Use the Microsoft Sentinel community connector for Defender Vulnerability
Management:

<https://github.com/Azure/Azure-Sentinel/tree/master/DataConnectors/M365Defender-VulnerabilityManagement>

Validate that the workspace receives these tables:

- `DeviceTvmSoftwareVulnerabilities`
- `DeviceTvmSoftwareVulnerabilitiesKB`
- `DeviceTvmSecureConfigurationAssessment`
- `DeviceTvmSecureConfigurationAssessmentKB`

Also enable the Microsoft Defender XDR / MDE device stream that provides
`DeviceInfo`. The normalization uses `DeviceInfo` for:

- workstation/server classification;
- MDE device tags and machine groups;
- internet-facing signal;
- MDE exposure level.

### 2. Defender for Cloud recommendations

Enable Defender for Cloud continuous export to the same Log Analytics workspace.
Export at least security recommendations so the workspace receives
`SecurityRecommendation`.

The native table provides recommendation severity and the assessed Azure
resource. Asset criticality and network exposure are usually not complete in
this table, so enrich the resources through the `TEM_AssetContext` watchlist or
through an upstream export that maps resource IDs to business tags.

### 3. Rapid7 web application vulnerabilities

Send Rapid7 web application findings to the custom table
`Rapid7AppSecFindings_CL`. The expected schema is documented in
`schemas/custom_tables.json`.

Use `deploy/rapid7-custom-ingestion.bicep` to create the custom table, data
collection endpoint, and data collection rule used by the Azure Monitor Logs
Ingestion API:

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file threat-exposure-management/deploy/rapid7-custom-ingestion.bicep \
  --parameters workspaceName=<log-analytics-workspace-name>
```

After deployment, post Rapid7 records to the DCR immutable ID returned by the
deployment output using stream `Custom-Rapid7AppSecFindings`.

Minimum required fields:

- `AssetId`
- `AssetName`
- `FindingId`
- `FindingTitle`
- `Severity` or `CvssScore`
- `Status`
- `FirstSeen` or `LastSeen`

Recommended enrichment fields:

- `AssetCriticality`
- `AssetExposure`
- `CvssVector`
- `Exploitability`
- `ExploitAvailable`
- `Tags`
- `Remediation`

For Rapid7, derive `AssetCriticality` from Rapid7 tags until a central CMDB or
asset inventory becomes authoritative. Derive `AssetExposure` from the
application URL, scan scope, network zone, or tag model.

### 4. Asset context watchlist

Create a Microsoft Sentinel watchlist named `TEM_AssetContext` using
`watchlists/TEM_AssetContext.csv` as the template.

Use this watchlist to fill gaps that source systems do not expose consistently:

- `AssetCriticality`: `Critical`, `High`, `Medium`, `Low`
- `AssetExposure`: `External`, `CriticalInternal`, `RegularInternal`,
  `Isolated`
- `AssetKind`: `Workstation`, `Server`, `WebApplication`, `CloudResource`
- `BusinessService`, `Owner`, and `Environment`

For Microsoft Defender data, prefer the MDE `DeviceId` as `AssetId`. For
Defender for Cloud, prefer the full Azure resource ID as `AssetId`. For Rapid7,
prefer the Rapid7 application or asset identifier.

## Normalized risk model

The KQL functions in `kql/tem_normalized_findings.kql` create a common schema:

| Column | Meaning |
| --- | --- |
| `SourceSystem` | `MDE`, `Rapid7`, or `DefenderForCloud` |
| `FindingType` | `Vulnerability` or `Recommendation` |
| `AssetId`, `AssetName`, `AssetKind` | Normalized asset identity |
| `AssetCriticality` | Business criticality from source tags or watchlist |
| `AssetExposure` | Network exposure category |
| `FindingId`, `FindingTitle`, `FindingCategory` | Normalized finding identity |
| `FindingSeverity` | Source severity mapped to a common label |
| `CvssScore`, `CvssVector` | CVSS details when available |
| `ExploitAvailable`, `Exploitability` | Exploit signal when available |
| `Status` | Open/active state from source |
| `FirstSeen`, `LastSeen` | Finding lifecycle timestamps |
| `Remediation` | Recommendation or remediation guidance |
| `RiskScore` | 0-100 prioritization score |

Risk score is calculated from:

1. finding criticality: CVSS, source severity, exploit availability, and
   exploitability;
2. asset criticality: critical business assets increase priority;
3. asset exposure: external and critical internal assets increase priority.

The exact formula lives in the `TEM_ApplyRiskScore` function so it can be tuned
without changing every workbook query.

## Deployment order

1. Enable the source connectors and custom ingestion.
2. Create the `TEM_AssetContext` watchlist.
3. Save each function in `kql/tem_normalized_findings.kql` as a Sentinel /
   Log Analytics function, in file order.
4. Run `kql/tem_data_quality.kql` to confirm required tables and enrichment
   fields are populated.
5. Import `workbooks/ThreatExposureManagement.workbook.json` as a Microsoft
   Sentinel workbook.

## Validation checklist

Run the data-quality queries before using the workbook for prioritization:

- all expected tables have recent rows;
- MDE rows join to `DeviceInfo`;
- Rapid7 rows include `AssetCriticality` and `AssetExposure`;
- Defender for Cloud recommendations join to asset context for priority assets;
- normalized rows have `RiskScore`, `AssetCriticality`, `AssetExposure`,
  `FindingSeverity`, and at least one lifecycle timestamp.

