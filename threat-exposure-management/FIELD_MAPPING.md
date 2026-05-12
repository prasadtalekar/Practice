# TEM source field mapping

This file maps the required prioritization inputs to source-system columns.

## Common prioritization inputs

| Prioritization input | MDE vulnerabilities | MDE recommendations | Rapid7 web applications | Defender for Cloud recommendations |
| --- | --- | --- | --- | --- |
| Asset identity | `DeviceTvmSoftwareVulnerabilities.DeviceId`, `DeviceName` | `DeviceTvmSecureConfigurationAssessment.DeviceId`, `DeviceName` | `Rapid7AppSecFindings_CL.AssetId`, `AssetName`, `Url`, `HostName` | `SecurityRecommendation.AssessedResourceId`, `DeviceId` |
| Asset type | `DeviceInfo.DeviceType`, `OSPlatform` | `DeviceInfo.DeviceType`, `OSPlatform` | `Rapid7AppSecFindings_CL.AssetType` | `TEM_AssetContext.AssetKind` |
| Asset criticality | `DeviceInfo.AssetValue`, `DeviceManualTags`, `DeviceDynamicTags`, `RegistryDeviceTag`, `TEM_AssetContext.AssetCriticality` | Same as MDE vulnerabilities | `Rapid7AppSecFindings_CL.AssetCriticality`, `Tags`, `TEM_AssetContext.AssetCriticality` | `TEM_AssetContext.AssetCriticality` |
| Asset exposure | `DeviceInfo.IsInternetFacing`, `ExposureLevel`, `TEM_AssetContext.AssetExposure` | Same as MDE vulnerabilities | `Rapid7AppSecFindings_CL.AssetExposure`, `Url`, `Tags`, `TEM_AssetContext.AssetExposure` | `TEM_AssetContext.AssetExposure` |
| Finding identity | `CveId` | `ConfigurationId` | `FindingId` | `RecommendationId`, `RecommendationName` |
| Finding criticality | `DeviceTvmSoftwareVulnerabilities.VulnerabilitySeverityLevel`, `DeviceTvmSoftwareVulnerabilitiesKB.CvssScore` | `ConfigurationImpact` | `Severity`, `CvssScore` | `RecommendationSeverity` |
| Exploitability | `DeviceTvmSoftwareVulnerabilitiesKB.IsExploitAvailable`, `CveTags` | Not available by default | `ExploitAvailable`, `Exploitability` | Not available by default |
| CVSS vector | Not exposed by current MDE Log Analytics table | Not applicable | `CvssVector` | Not applicable |
| Remediation | `RecommendedSecurityUpdate`, `RecommendedSecurityUpdateId` | `DeviceTvmSecureConfigurationAssessmentKB.RemediationOptions` | `Remediation` | `Description` |
| Lifecycle | `TimeGenerated` | `Timestamp`, `TimeGenerated` | `FirstSeen`, `LastSeen`, `TimeGenerated` | `DiscoveredTimeUTC`, `FirstEvaluationDate`, `StatusChangeDate`, `TimeGenerated` |

## Required enrichment decisions

1. **Asset criticality**
   - MDE: use Defender asset value and tags first; override with
     `TEM_AssetContext` for high-value systems.
   - Rapid7: populate `AssetCriticality` from Rapid7 tags during ingestion.
   - Defender for Cloud: populate through `TEM_AssetContext` because the
     recommendation table does not reliably include business criticality.

2. **Asset exposure**
   - MDE: `IsInternetFacing=true` maps to `External`; `ExposureLevel=High`
     maps to `CriticalInternal` unless overridden.
   - Rapid7: populate from URL/scan scope/tags during ingestion.
   - Defender for Cloud: populate through `TEM_AssetContext` or a separate
     resource inventory enrichment.

3. **Finding criticality**
   - Prefer CVSS when available.
   - Fall back to source severity or impact score.
   - Add exploit bonus when exploit availability or exploitability is known.

4. **Missing data**
   - Use `kql/tem_data_quality.kql` to identify missing required enrichment
     before relying on the workbook for prioritization.

