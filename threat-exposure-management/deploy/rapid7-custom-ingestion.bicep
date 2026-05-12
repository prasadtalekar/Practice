@description('Azure region for the data collection endpoint and rule.')
param location string = resourceGroup().location

@description('Name of the existing Log Analytics workspace that will receive Rapid7 TEM findings.')
param workspaceName string

@description('Name of the data collection endpoint for Rapid7 TEM ingestion.')
param dataCollectionEndpointName string = 'dce-tem-rapid7'

@description('Name of the data collection rule for Rapid7 TEM ingestion.')
param dataCollectionRuleName string = 'dcr-tem-rapid7'

@description('Interactive retention in days for the Rapid7 custom table.')
@minValue(4)
@maxValue(730)
param retentionInDays int = 90

@description('Total retention in days for the Rapid7 custom table.')
@minValue(4)
@maxValue(2555)
param totalRetentionInDays int = 365

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource rapid7Table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'Rapid7AppSecFindings_CL'
  properties: {
    retentionInDays: retentionInDays
    totalRetentionInDays: totalRetentionInDays
    schema: {
      name: 'Rapid7AppSecFindings_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'IngestionRunId', type: 'string' }
        { name: 'SourceSystem', type: 'string' }
        { name: 'Rapid7Region', type: 'string' }
        { name: 'ScanId', type: 'string' }
        { name: 'AssetId', type: 'string' }
        { name: 'AssetName', type: 'string' }
        { name: 'AssetType', type: 'string' }
        { name: 'AssetCriticality', type: 'string' }
        { name: 'AssetExposure', type: 'string' }
        { name: 'ApplicationName', type: 'string' }
        { name: 'Url', type: 'string' }
        { name: 'HostName', type: 'string' }
        { name: 'Port', type: 'int' }
        { name: 'Protocol', type: 'string' }
        { name: 'Tags', type: 'dynamic' }
        { name: 'FindingId', type: 'string' }
        { name: 'FindingTitle', type: 'string' }
        { name: 'FindingDescription', type: 'string' }
        { name: 'FindingCategory', type: 'string' }
        { name: 'Severity', type: 'string' }
        { name: 'CvssScore', type: 'real' }
        { name: 'CvssVector', type: 'string' }
        { name: 'Exploitability', type: 'string' }
        { name: 'ExploitAvailable', type: 'bool' }
        { name: 'Status', type: 'string' }
        { name: 'FirstSeen', type: 'datetime' }
        { name: 'LastSeen', type: 'datetime' }
        { name: 'Remediation', type: 'string' }
        { name: 'Evidence', type: 'dynamic' }
        { name: 'RawRecord', type: 'dynamic' }
      ]
    }
  }
}

resource endpoint 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: dataCollectionEndpointName
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource rule 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dataCollectionRuleName
  location: location
  properties: {
    dataCollectionEndpointId: endpoint.id
    streamDeclarations: {
      'Custom-Rapid7AppSecFindings': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'IngestionRunId', type: 'string' }
          { name: 'SourceSystem', type: 'string' }
          { name: 'Rapid7Region', type: 'string' }
          { name: 'ScanId', type: 'string' }
          { name: 'AssetId', type: 'string' }
          { name: 'AssetName', type: 'string' }
          { name: 'AssetType', type: 'string' }
          { name: 'AssetCriticality', type: 'string' }
          { name: 'AssetExposure', type: 'string' }
          { name: 'ApplicationName', type: 'string' }
          { name: 'Url', type: 'string' }
          { name: 'HostName', type: 'string' }
          { name: 'Port', type: 'int' }
          { name: 'Protocol', type: 'string' }
          { name: 'Tags', type: 'dynamic' }
          { name: 'FindingId', type: 'string' }
          { name: 'FindingTitle', type: 'string' }
          { name: 'FindingDescription', type: 'string' }
          { name: 'FindingCategory', type: 'string' }
          { name: 'Severity', type: 'string' }
          { name: 'CvssScore', type: 'real' }
          { name: 'CvssVector', type: 'string' }
          { name: 'Exploitability', type: 'string' }
          { name: 'ExploitAvailable', type: 'bool' }
          { name: 'Status', type: 'string' }
          { name: 'FirstSeen', type: 'datetime' }
          { name: 'LastSeen', type: 'datetime' }
          { name: 'Remediation', type: 'string' }
          { name: 'Evidence', type: 'dynamic' }
          { name: 'RawRecord', type: 'dynamic' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'temWorkspace'
          workspaceResourceId: workspace.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-Rapid7AppSecFindings'
        ]
        destinations: [
          'temWorkspace'
        ]
        outputStream: 'Custom-Rapid7AppSecFindings_CL'
        transformKql: 'source | extend TimeGenerated = coalesce(TimeGenerated, now()), SourceSystem = coalesce(SourceSystem, "Rapid7")'
      }
    ]
  }
  dependsOn: [
    rapid7Table
  ]
}

output immutableId string = rule.properties.immutableId
output logsIngestionEndpoint string = endpoint.properties.logsIngestion.endpoint
output rapid7TableName string = rapid7Table.name
