# Threat Exposure Management - MDVM critical internet-facing recommendations

KQL queries for Azure Log Analytics to correlate internet-facing devices with
critical Microsoft Defender Vulnerability Management (MDVM) recommendations from
`MDVMRecommendations_CL`.

Run the schema check first and adjust the aliases in the `extend` blocks if your
custom table uses different field names. Custom Log Analytics columns commonly
end in `_s`, `_d`, `_b`, or `_g`.

## 0. Confirm the custom table schema

```kusto
MDVMRecommendations_CL
| getschema
| project ColumnName, ColumnType
| order by ColumnName asc
```

Optional sample data check:

```kusto
MDVMRecommendations_CL
| take 20
```

## 1. Critical recommendations on internet-facing devices

Use this when `DeviceInfo` is available in the same workspace. The query uses
`DeviceInfo.IsInternetFacing` as the authoritative internet-facing signal and
joins it to critical rows in `MDVMRecommendations_CL`.

```kusto
let Lookback = 30d;
let InternetFacingDevices =
    DeviceInfo
    | where TimeGenerated >= ago(Lookback)
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | where IsInternetFacing == true
    | project
        DeviceId,
        InternetFacingDeviceName = DeviceName,
        PublicIP,
        OSPlatform,
        OSVersion,
        MachineGroup,
        ExposureLevel,
        AssetValue;
let CriticalRecommendations =
    MDVMRecommendations_CL
    | where TimeGenerated >= ago(Lookback)
    | extend
        DeviceId = coalesce(
            tostring(column_ifexists("DeviceId_s", "")),
            tostring(column_ifexists("DeviceId_g", "")),
            tostring(column_ifexists("DeviceId", ""))),
        DeviceName = coalesce(
            tostring(column_ifexists("DeviceName_s", "")),
            tostring(column_ifexists("MachineName_s", "")),
            tostring(column_ifexists("Computer", "")),
            tostring(column_ifexists("DeviceName", ""))),
        RecommendationId = coalesce(
            tostring(column_ifexists("RecommendationId_s", "")),
            tostring(column_ifexists("recommendationId_s", "")),
            tostring(column_ifexists("Id_s", "")),
            tostring(column_ifexists("RecommendationId", ""))),
        RecommendationName = coalesce(
            tostring(column_ifexists("RecommendationName_s", "")),
            tostring(column_ifexists("recommendationName_s", "")),
            tostring(column_ifexists("Title_s", "")),
            tostring(column_ifexists("RecommendationName", ""))),
        Severity = coalesce(
            tostring(column_ifexists("Severity_s", "")),
            tostring(column_ifexists("RecommendationSeverity_s", "")),
            tostring(column_ifexists("VulnerabilitySeverityLevel_s", "")),
            tostring(column_ifexists("Severity", ""))),
        ProductName = coalesce(
            tostring(column_ifexists("ProductName_s", "")),
            tostring(column_ifexists("SoftwareName_s", "")),
            tostring(column_ifexists("productName_s", "")),
            tostring(column_ifexists("ProductName", ""))),
        CveId = coalesce(
            tostring(column_ifexists("CveId_s", "")),
            tostring(column_ifexists("CveIds_s", "")),
            tostring(column_ifexists("CVE_s", "")),
            tostring(column_ifexists("CveId", ""))),
        Remediation = coalesce(
            tostring(column_ifexists("Remediation_s", "")),
            tostring(column_ifexists("RecommendedAction_s", "")),
            tostring(column_ifexists("RemediationText_s", "")),
            tostring(column_ifexists("Remediation", ""))),
        RecommendationStatus = coalesce(
            tostring(column_ifexists("Status_s", "")),
            tostring(column_ifexists("RecommendationStatus_s", "")),
            tostring(column_ifexists("Status", ""))),
        ExposureImpact = coalesce(
            todouble(column_ifexists("ExposureImpact_d", real(null))),
            todouble(column_ifexists("ExposureImpact", real(null)))),
        CvssScore = coalesce(
            todouble(column_ifexists("CvssScore_d", real(null))),
            todouble(column_ifexists("CVSSScore_d", real(null))),
            todouble(column_ifexists("CvssScore_s", "")),
            todouble(column_ifexists("CvssScore", real(null))))
    | where Severity =~ "Critical" or CvssScore >= 9.0
    | where isempty(RecommendationStatus) or RecommendationStatus !in~ ("Completed", "Resolved", "Remediated", "Inactive")
    | summarize arg_max(TimeGenerated, *) by DeviceId, DeviceName, RecommendationId, RecommendationName, ProductName, CveId;
CriticalRecommendations
| join kind=innerunique (InternetFacingDevices) on DeviceId
| extend DeviceName = coalesce(InternetFacingDeviceName, DeviceName)
| project
    TimeGenerated,
    DeviceId,
    DeviceName,
    PublicIP,
    OSPlatform,
    OSVersion,
    MachineGroup,
    ExposureLevel,
    AssetValue,
    RecommendationId,
    RecommendationName,
    Severity,
    CvssScore,
    ProductName,
    CveId,
    ExposureImpact,
    Remediation,
    RecommendationStatus
| order by ExposureImpact desc, CvssScore desc, DeviceName asc, RecommendationName asc
```

## 2. Workbook summary by internet-facing device

Use this for a dashboard grid or tile that lists highest-risk internet-facing
assets first.

```kusto
let Lookback = 30d;
let InternetFacingDevices =
    DeviceInfo
    | where TimeGenerated >= ago(Lookback)
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | where IsInternetFacing == true
    | project DeviceId, DeviceName, PublicIP, MachineGroup, ExposureLevel, AssetValue;
let CriticalRecommendations =
    MDVMRecommendations_CL
    | where TimeGenerated >= ago(Lookback)
    | extend
        DeviceId = coalesce(tostring(column_ifexists("DeviceId_s", "")), tostring(column_ifexists("DeviceId_g", "")), tostring(column_ifexists("DeviceId", ""))),
        RecommendationId = coalesce(tostring(column_ifexists("RecommendationId_s", "")), tostring(column_ifexists("recommendationId_s", "")), tostring(column_ifexists("Id_s", "")), tostring(column_ifexists("RecommendationId", ""))),
        RecommendationName = coalesce(tostring(column_ifexists("RecommendationName_s", "")), tostring(column_ifexists("recommendationName_s", "")), tostring(column_ifexists("Title_s", "")), tostring(column_ifexists("RecommendationName", ""))),
        Severity = coalesce(tostring(column_ifexists("Severity_s", "")), tostring(column_ifexists("RecommendationSeverity_s", "")), tostring(column_ifexists("VulnerabilitySeverityLevel_s", "")), tostring(column_ifexists("Severity", ""))),
        ProductName = coalesce(tostring(column_ifexists("ProductName_s", "")), tostring(column_ifexists("SoftwareName_s", "")), tostring(column_ifexists("productName_s", "")), tostring(column_ifexists("ProductName", ""))),
        CveId = coalesce(tostring(column_ifexists("CveId_s", "")), tostring(column_ifexists("CveIds_s", "")), tostring(column_ifexists("CVE_s", "")), tostring(column_ifexists("CveId", ""))),
        ExposureImpact = coalesce(todouble(column_ifexists("ExposureImpact_d", real(null))), todouble(column_ifexists("ExposureImpact", real(null)))),
        CvssScore = coalesce(todouble(column_ifexists("CvssScore_d", real(null))), todouble(column_ifexists("CVSSScore_d", real(null))), todouble(column_ifexists("CvssScore_s", "")), todouble(column_ifexists("CvssScore", real(null))))
    | where Severity =~ "Critical" or CvssScore >= 9.0
    | summarize arg_max(TimeGenerated, *) by DeviceId, RecommendationId, RecommendationName, ProductName, CveId;
CriticalRecommendations
| join kind=inner (InternetFacingDevices) on DeviceId
| summarize
    CriticalRecommendationCount = dcount(RecommendationId),
    CriticalFindingRows = count(),
    AffectedProducts = make_set(ProductName, 50),
    CriticalCVEs = make_set(CveId, 100),
    TopRecommendations = make_set(RecommendationName, 20),
    MaxCvssScore = max(CvssScore),
    MaxExposureImpact = max(ExposureImpact)
    by DeviceId, DeviceName, PublicIP, MachineGroup, ExposureLevel, AssetValue
| order by CriticalRecommendationCount desc, MaxExposureImpact desc, MaxCvssScore desc, DeviceName asc
```

## 3. Workbook summary by critical recommendation

Use this to show which critical recommendations affect the most
internet-facing devices.

```kusto
let Lookback = 30d;
let InternetFacingDevices =
    DeviceInfo
    | where TimeGenerated >= ago(Lookback)
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | where IsInternetFacing == true
    | project DeviceId, DeviceName, PublicIP, MachineGroup;
let CriticalRecommendations =
    MDVMRecommendations_CL
    | where TimeGenerated >= ago(Lookback)
    | extend
        DeviceId = coalesce(tostring(column_ifexists("DeviceId_s", "")), tostring(column_ifexists("DeviceId_g", "")), tostring(column_ifexists("DeviceId", ""))),
        RecommendationId = coalesce(tostring(column_ifexists("RecommendationId_s", "")), tostring(column_ifexists("recommendationId_s", "")), tostring(column_ifexists("Id_s", "")), tostring(column_ifexists("RecommendationId", ""))),
        RecommendationName = coalesce(tostring(column_ifexists("RecommendationName_s", "")), tostring(column_ifexists("recommendationName_s", "")), tostring(column_ifexists("Title_s", "")), tostring(column_ifexists("RecommendationName", ""))),
        Severity = coalesce(tostring(column_ifexists("Severity_s", "")), tostring(column_ifexists("RecommendationSeverity_s", "")), tostring(column_ifexists("VulnerabilitySeverityLevel_s", "")), tostring(column_ifexists("Severity", ""))),
        ProductName = coalesce(tostring(column_ifexists("ProductName_s", "")), tostring(column_ifexists("SoftwareName_s", "")), tostring(column_ifexists("productName_s", "")), tostring(column_ifexists("ProductName", ""))),
        CveId = coalesce(tostring(column_ifexists("CveId_s", "")), tostring(column_ifexists("CveIds_s", "")), tostring(column_ifexists("CVE_s", "")), tostring(column_ifexists("CveId", ""))),
        Remediation = coalesce(tostring(column_ifexists("Remediation_s", "")), tostring(column_ifexists("RecommendedAction_s", "")), tostring(column_ifexists("RemediationText_s", "")), tostring(column_ifexists("Remediation", ""))),
        ExposureImpact = coalesce(todouble(column_ifexists("ExposureImpact_d", real(null))), todouble(column_ifexists("ExposureImpact", real(null)))),
        CvssScore = coalesce(todouble(column_ifexists("CvssScore_d", real(null))), todouble(column_ifexists("CVSSScore_d", real(null))), todouble(column_ifexists("CvssScore_s", "")), todouble(column_ifexists("CvssScore", real(null))))
    | where Severity =~ "Critical" or CvssScore >= 9.0
    | summarize arg_max(TimeGenerated, *) by DeviceId, RecommendationId, RecommendationName, ProductName, CveId;
CriticalRecommendations
| join kind=inner (InternetFacingDevices) on DeviceId
| summarize
    InternetFacingDeviceCount = dcount(DeviceId),
    Devices = make_set(DeviceName, 100),
    PublicIPs = make_set(PublicIP, 100),
    MachineGroups = make_set(MachineGroup, 50),
    CVEs = make_set(CveId, 100),
    MaxCvssScore = max(CvssScore),
    MaxExposureImpact = max(ExposureImpact),
    AnyRemediation = any(Remediation)
    by RecommendationId, RecommendationName, ProductName
| order by InternetFacingDeviceCount desc, MaxExposureImpact desc, MaxCvssScore desc, RecommendationName asc
```

## 4. Fallback if `MDVMRecommendations_CL` already has an internet-facing field

Use this if the custom table contains a boolean or string field such as
`IsInternetFacing_b`, `IsInternetFacing_s`, or `InternetFacing_s` and you do not
need to join to `DeviceInfo`.

```kusto
let Lookback = 30d;
MDVMRecommendations_CL
| where TimeGenerated >= ago(Lookback)
| extend
    DeviceId = coalesce(tostring(column_ifexists("DeviceId_s", "")), tostring(column_ifexists("DeviceId_g", "")), tostring(column_ifexists("DeviceId", ""))),
    DeviceName = coalesce(tostring(column_ifexists("DeviceName_s", "")), tostring(column_ifexists("MachineName_s", "")), tostring(column_ifexists("Computer", "")), tostring(column_ifexists("DeviceName", ""))),
    RecommendationId = coalesce(tostring(column_ifexists("RecommendationId_s", "")), tostring(column_ifexists("recommendationId_s", "")), tostring(column_ifexists("Id_s", "")), tostring(column_ifexists("RecommendationId", ""))),
    RecommendationName = coalesce(tostring(column_ifexists("RecommendationName_s", "")), tostring(column_ifexists("recommendationName_s", "")), tostring(column_ifexists("Title_s", "")), tostring(column_ifexists("RecommendationName", ""))),
    Severity = coalesce(tostring(column_ifexists("Severity_s", "")), tostring(column_ifexists("RecommendationSeverity_s", "")), tostring(column_ifexists("VulnerabilitySeverityLevel_s", "")), tostring(column_ifexists("Severity", ""))),
    ProductName = coalesce(tostring(column_ifexists("ProductName_s", "")), tostring(column_ifexists("SoftwareName_s", "")), tostring(column_ifexists("productName_s", "")), tostring(column_ifexists("ProductName", ""))),
    CveId = coalesce(tostring(column_ifexists("CveId_s", "")), tostring(column_ifexists("CveIds_s", "")), tostring(column_ifexists("CVE_s", "")), tostring(column_ifexists("CveId", ""))),
    IsInternetFacingRaw = coalesce(tostring(column_ifexists("IsInternetFacing_b", "")), tostring(column_ifexists("IsInternetFacing_s", "")), tostring(column_ifexists("InternetFacing_s", "")), tostring(column_ifexists("InternetFacing", ""))),
    ExposureImpact = coalesce(todouble(column_ifexists("ExposureImpact_d", real(null))), todouble(column_ifexists("ExposureImpact", real(null)))),
    CvssScore = coalesce(todouble(column_ifexists("CvssScore_d", real(null))), todouble(column_ifexists("CVSSScore_d", real(null))), todouble(column_ifexists("CvssScore_s", "")), todouble(column_ifexists("CvssScore", real(null))))
| where IsInternetFacingRaw in~ ("true", "1", "yes")
| where Severity =~ "Critical" or CvssScore >= 9.0
| summarize arg_max(TimeGenerated, *) by DeviceId, DeviceName, RecommendationId, RecommendationName, ProductName, CveId
| project
    TimeGenerated,
    DeviceId,
    DeviceName,
    RecommendationId,
    RecommendationName,
    Severity,
    CvssScore,
    ProductName,
    CveId,
    ExposureImpact
| order by ExposureImpact desc, CvssScore desc, DeviceName asc, RecommendationName asc
```

## 5. Workbook count tiles

Internet-facing devices with at least one critical MDVM recommendation:

```kusto
let Lookback = 30d;
let InternetFacingDevices =
    DeviceInfo
    | where TimeGenerated >= ago(Lookback)
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | where IsInternetFacing == true
    | project DeviceId;
MDVMRecommendations_CL
| where TimeGenerated >= ago(Lookback)
| extend
    DeviceId = coalesce(tostring(column_ifexists("DeviceId_s", "")), tostring(column_ifexists("DeviceId_g", "")), tostring(column_ifexists("DeviceId", ""))),
    Severity = coalesce(tostring(column_ifexists("Severity_s", "")), tostring(column_ifexists("RecommendationSeverity_s", "")), tostring(column_ifexists("VulnerabilitySeverityLevel_s", "")), tostring(column_ifexists("Severity", ""))),
    CvssScore = coalesce(todouble(column_ifexists("CvssScore_d", real(null))), todouble(column_ifexists("CVSSScore_d", real(null))), todouble(column_ifexists("CvssScore_s", "")), todouble(column_ifexists("CvssScore", real(null))))
| where Severity =~ "Critical" or CvssScore >= 9.0
| join kind=innerunique (InternetFacingDevices) on DeviceId
| summarize InternetFacingDevicesWithCriticalRecommendations = dcount(DeviceId)
```

Critical recommendation count across internet-facing devices:

```kusto
let Lookback = 30d;
let InternetFacingDevices =
    DeviceInfo
    | where TimeGenerated >= ago(Lookback)
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | where IsInternetFacing == true
    | project DeviceId;
MDVMRecommendations_CL
| where TimeGenerated >= ago(Lookback)
| extend
    DeviceId = coalesce(tostring(column_ifexists("DeviceId_s", "")), tostring(column_ifexists("DeviceId_g", "")), tostring(column_ifexists("DeviceId", ""))),
    RecommendationId = coalesce(tostring(column_ifexists("RecommendationId_s", "")), tostring(column_ifexists("recommendationId_s", "")), tostring(column_ifexists("Id_s", "")), tostring(column_ifexists("RecommendationId", ""))),
    Severity = coalesce(tostring(column_ifexists("Severity_s", "")), tostring(column_ifexists("RecommendationSeverity_s", "")), tostring(column_ifexists("VulnerabilitySeverityLevel_s", "")), tostring(column_ifexists("Severity", ""))),
    CvssScore = coalesce(todouble(column_ifexists("CvssScore_d", real(null))), todouble(column_ifexists("CVSSScore_d", real(null))), todouble(column_ifexists("CvssScore_s", "")), todouble(column_ifexists("CvssScore", real(null))))
| where Severity =~ "Critical" or CvssScore >= 9.0
| join kind=inner (InternetFacingDevices) on DeviceId
| summarize CriticalRecommendationsOnInternetFacingDevices = dcount(RecommendationId)
```
