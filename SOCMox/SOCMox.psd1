@{
    # Version number of this module.
    ModuleVersion = '1.0.0'

    # Supported PowerShell engine version
    PowerShellVersion = '5.1'

    # ID used to uniquely identify this module
    GUID = '9d3fb153-6a3f-42ee-916c-e66601b0f1fb'

    # Author of this module
    Author = 'SOC MOX'

    # Company or vendor of this module
    CompanyName = 'SOC MOX'

    # Copyright statement for this module
    Copyright = '(c) 2026 SOC MOX. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Security Operations Center (SOC) helper tools including VirusTotal lookups, Threat Intelligence summaries, and WHOIS query integration.'

    # Script module or binary module file associated with this manifest.
    RootModule = 'SOCMox.psm1'

    # Functions to export from this module, for best performance, do not use wildcards and do not leave list empty.
    FunctionsToExport = @(
        'Get-VTlookup'
        'Get-TISummary'
        'Get-whois'
        'Set-VTApiKey'
        'Get-News'
        'Get-CVEDetails'
        'Get-GeoIP'
        'New-TriagePrompt'
        'Get-CloudStatus'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not leave list empty.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online repositories.
            Tags = @('SOC', 'Security', 'DFIR', 'VirusTotal', 'WHOIS', 'ThreatIntel')
        }
    }
}
