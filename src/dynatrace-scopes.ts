enum Scope {
    "ActiveGateCertManagement" = "ActiveGateCertManagement",
    "AdvancedSyntheticIntegration" = "AdvancedSyntheticIntegration",
    "AppMonIntegration" = "AppMonIntegration",
    "CaptureRequestData" = "CaptureRequestData",
    "DTAQLAccess" = "DTAQLAccess",
    "DataExport" = "DataExport",
    "DataImport" = "DataImport",
    "DataPrivacy" = "DataPrivacy",
    "Davis" = "Davis",
    "DcrumIntegration" = "DcrumIntegration",
    "DiagnosticExport" = "DiagnosticExport",
    "DssFileManagement" = "DssFileManagement",
    "ExternalSyntheticIntegration" = "ExternalSyntheticIntegration",
    "InstallerDownload" = "InstallerDownload",
    "LogExport" = "LogExport",
    "MemoryDump" = "MemoryDump",
    "Mobile" = "Mobile",
    "PluginUpload" = "PluginUpload",
    "ReadConfig" = "ReadConfig",
    "ReadSyntheticData" = "ReadSyntheticData",
    "RestRequestForwarding" = "RestRequestForwarding",
    "RumBrowserExtension" = "RumBrowserExtension",
    "RumJavaScriptTagManagement" = "RumJavaScriptTagManagement",
    "SupportAlert" = "SupportAlert",
    "TenantTokenManagement" = "TenantTokenManagement",
    "UserSessionAnonymization" = "UserSessionAnonymization",
    "ViewDashboard" = "ViewDashboard",
    "ViewReport" = "ViewReport",
    "WriteConfig" = "WriteConfig",
    "WriteSyntheticData" = "WriteSyntheticData",
    "activeGateTokenManagement.create" = "activeGateTokenManagement.create",
    "activeGateTokenManagement.read" = "activeGateTokenManagement.read",
    "activeGateTokenManagement.write" = "activeGateTokenManagement.write",
    "activeGates.read" = "activeGates.read",
    "activeGates.write" = "activeGates.write",
    "apiTokens.read" = "apiTokens.read",
    "apiTokens.write" = "apiTokens.write",
    "auditLogs.read" = "auditLogs.read",
    "credentialVault.read" = "credentialVault.read",
    "credentialVault.write" = "credentialVault.write",
    "entities.read" = "entities.read",
    "entities.write" = "entities.write",
    "events.ingest" = "events.ingest",
    "events.read" = "events.read",
    "extensionConfigurations.read" = "extensionConfigurations.read",
    "extensionConfigurations.write" = "extensionConfigurations.write",
    "extensionEnvironment.read" = "extensionEnvironment.read",
    "extensionEnvironment.write" = "extensionEnvironment.write",
    "extensions.read" = "extensions.read",
    "extensions.write" = "extensions.write",
    "logs.ingest" = "logs.ingest",
    "logs.read" = "logs.read",
    "metrics.ingest" = "metrics.ingest",
    "metrics.read" = "metrics.read",
    "metrics.write" = "metrics.write",
    "networkZones.read" = "networkZones.read",
    "networkZones.write" = "networkZones.write",
    "openTelemetryTrace.ingest" = "openTelemetryTrace.ingest",
    "problems.read" = "problems.read",
    "problems.write" = "problems.write",
    "releases.read" = "releases.read",
    "securityProblems.read" = "securityProblems.read",
    "securityProblems.write" = "securityProblems.write",
    "settings.read" = "settings.read",
    "settings.write" = "settings.write",
    "slo.read" = "slo.read",
    "slo.write" = "slo.write",
    "syntheticLocations.read" = "syntheticLocations.read",
    "syntheticLocations.write" = "syntheticLocations.write",
    "tenantTokenRotation.write" = "tenantTokenRotation.write",
}

export type ScopeMap = {
    [value in Scope]: Array<string>;
}