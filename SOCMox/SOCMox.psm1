# SOC MOX PowerShell Module
# Contains cmdlets for SOC Analyst helper tools.

$ConfigPath = Join-Path $HOME ".socmox_config.json"

# Helper function to load configuration
function Get-SOCMoxConfig {
    if (Test-Path $ConfigPath) {
        try {
            Get-Content $ConfigPath -Raw | ConvertFrom-Json
        } catch {
            @{
                VT_API_Key = ""
            }
        }
    } else {
        @{
            VT_API_Key = ""
        }
    }
}

# Helper function to save configuration
function Save-SOCMoxConfig {
    param(
        [Parameter(Mandatory = $true)]
        $Config
    )
    try {
        $Config | ConvertTo-Json | Out-File $ConfigPath -Encoding utf8 -Force
    } catch {
        Write-Warning "Could not save configuration: $_"
    }
}

# Helper function to classify indicator types
function Get-IndicatorType {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Indicator
    )
    $Clean = $Indicator.Trim()
    
    # IPv4 check
    if ($Clean -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
        return "IP"
    }
    
    # MD5 check
    if ($Clean -match '^[a-fA-F0-9]{32}$') {
        return "Hash"
    }
    
    # SHA-1 check
    if ($Clean -match '^[a-fA-F0-9]{40}$') {
        return "Hash"
    }
    
    # SHA-256 check
    if ($Clean -match '^[a-fA-F0-9]{64}$') {
        return "Hash"
    }
    
    # Domain check (simple match, must contain a dot and at least 2 char TLD)
    if ($Clean -match '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$') {
        return "Domain"
    }
    
    return "Unknown"
}

# ----------------------------------------------------
# 1. Set-VTApiKey
# ----------------------------------------------------
function Set-VTApiKey {
    <#
    .SYNOPSIS
        Configure and persist the VirusTotal API key.
    .DESCRIPTION
        Saves the provided VirusTotal API key to a local configuration file (~/.socmox_config.json)
        and sets it for the current environment.
    .PARAMETER Key
        The VirusTotal API key.
    .EXAMPLE
        Set-VTApiKey -Key "abcdef1234567890..."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Key
    )
    process {
        $Config = Get-SOCMoxConfig
        if ($Config -is [PSCustomObject]) {
            $Config = @{ VT_API_Key = $Config.VT_API_Key }
        }
        $Config.VT_API_Key = $Key
        Save-SOCMoxConfig -Config $Config
        $env:VIRUSTOTAL_API_KEY = $Key
        Write-Host "VirusTotal API Key has been successfully saved to configuration." -ForegroundColor Green
    }
}

# ----------------------------------------------------
# 2. Get-VTlookup
# ----------------------------------------------------
function Get-VTlookup {
    <#
    .SYNOPSIS
        Look up a file hash, IP address, or domain on VirusTotal.
    .DESCRIPTION
        Queries the VirusTotal v3 API to retrieve reputation and engine detection stats
        for an indicator (IP, Domain, MD5, SHA-1, or SHA-256 hash).
    .PARAMETER Indicator
        The IP address, domain name, or file hash to look up.
    .PARAMETER ApiKey
        Optional VirusTotal API key. If not provided, it reads from environmental variables or configuration.
    .EXAMPLE
        Get-VTlookup -Indicator "8.8.8.8"
    .EXAMPLE
        Get-VTlookup "google.com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Indicator,

        [Parameter(Mandatory = $false)]
        [string]$ApiKey
    )
    process {
        # Trim whitespace
        $Indicator = $Indicator.Trim()

        # Resolve API Key
        if (-not $ApiKey) {
            $ApiKey = $env:VIRUSTOTAL_API_KEY
            if (-not $ApiKey) {
                $Config = Get-SOCMoxConfig
                if ($Config -and $Config.VT_API_Key) {
                    $ApiKey = $Config.VT_API_Key
                }
            }
        }

        if (-not $ApiKey) {
            Write-Warning "VirusTotal API Key is not configured."
            Write-Host "Please set your API key using one of the following methods:" -ForegroundColor Yellow
            Write-Host "  1. Set environment variable: `$env:VIRUSTOTAL_API_KEY = 'your_key'" -ForegroundColor Yellow
            Write-Host "  2. Save it to configuration: Set-VTApiKey -Key 'your_key'" -ForegroundColor Yellow
            Write-Host "  3. Pass it to the cmdlet: Get-VTlookup -Indicator '$Indicator' -ApiKey 'your_key'" -ForegroundColor Yellow
            return
        }

        $Type = Get-IndicatorType -Indicator $Indicator
        if ($Type -eq "Unknown") {
            Write-Error "Invalid indicator format: '$Indicator'. Must be an IP, Domain, or Hash."
            return
        }

        $BaseUrl = "https://www.virustotal.com/api/v3"
        switch ($Type) {
            "IP" { $Endpoint = "$BaseUrl/ip_addresses/$Indicator" }
            "Domain" { $Endpoint = "$BaseUrl/domains/$Indicator" }
            "Hash" { $Endpoint = "$BaseUrl/files/$Indicator" }
        }

        $Headers = @{
            "x-apikey" = $ApiKey
        }

        Write-Verbose "Querying VirusTotal API: $Endpoint"
        try {
            $Result = Invoke-RestMethod -Uri $Endpoint -Headers $Headers -Method Get
            $Data = $Result.data
            
            # Parse stats
            $Stats = $Data.attributes.last_analysis_stats
            $Reputation = $Data.attributes.reputation
            
            # Print visual console summary
            Write-Host "`n=== VirusTotal Analysis Summary ===" -ForegroundColor Cyan
            Write-Host "Indicator:  $Indicator ($Type)"
            Write-Host "Reputation: $Reputation (VT Score)"
            
            $Color = "Green"
            if ($Stats.malicious -gt 0) { $Color = "Red" }
            elseif ($Stats.suspicious -gt 0) { $Color = "Yellow" }
            
            $Total = $Stats.malicious + $Stats.harmless + $Stats.undetected + $Stats.suspicious
            Write-Host "Detections: $($Stats.malicious) / $Total engines flagged as malicious" -ForegroundColor $Color
            Write-Host "Breakdown:  Malicious: $($Stats.malicious) | Suspicious: $($Stats.suspicious) | Harmless: $($Stats.harmless) | Undetected: $($Stats.undetected)"
            
            if ($Data.attributes.meaningful_name) {
                Write-Host "Filename:   $($Data.attributes.meaningful_name)"
            }
            if ($Data.attributes.as_owner) {
                Write-Host "ASN Owner:  $($Data.attributes.as_owner) (AS$($Data.attributes.asn))"
            }
            
            $VTUrl = "https://www.virustotal.com/gui/$($Type.ToLower() + 's')/$Indicator"
            Write-Host "Report URL: $VTUrl" -ForegroundColor Cyan
            Write-Host "===================================`n"

            # Return custom object
            return [PSCustomObject]@{
                Indicator  = $Indicator
                Type       = $Type
                Reputation = $Reputation
                Malicious  = $Stats.malicious
                Suspicious = $Stats.suspicious
                Harmless   = $Stats.harmless
                Undetected = $Stats.undetected
                ReportUrl  = $VTUrl
                RawData    = $Data
            }
        }
        catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 404) {
                Write-Warning "Indicator '$Indicator' not found in VirusTotal database."
                return [PSCustomObject]@{
                    Indicator  = $Indicator
                    Type       = $Type
                    Reputation = $null
                    Malicious  = 0
                    Suspicious = 0
                    Harmless   = 0
                    Undetected = 0
                    ReportUrl  = "https://www.virustotal.com/gui/$($Type.ToLower() + 's')/$Indicator"
                    RawData    = $null
                }
            } else {
                Write-Error "Failed to query VirusTotal: $_"
            }
        }
    }
}

# ----------------------------------------------------
# 3. Get-whois
# ----------------------------------------------------
function Get-whois {
    <#
    .SYNOPSIS
        Perform a WHOIS or RDAP lookup on an IP address or domain.
    .DESCRIPTION
        Queries the Registration Data Access Protocol (RDAP) endpoints to get structured details.
        Falls back to local CLI 'whois' tool if RDAP queries fail.
    .PARAMETER Indicator
        The IP address or domain to query.
    .EXAMPLE
        Get-whois "google.com"
    .EXAMPLE
        Get-whois "8.8.8.8"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Indicator
    )
    process {
        $Indicator = $Indicator.Trim()
        $Type = Get-IndicatorType -Indicator $Indicator
        
        if ($Type -ne "IP" -and $Type -ne "Domain") {
            Write-Error "Invalid indicator for WHOIS/RDAP: '$Indicator'. Must be an IP address or domain."
            return
        }

        # Initialize outputs
        $OrgName = "Unknown"
        $Country = "Unknown"
        $Registrar = "Unknown"
        $Created = "Unknown"
        $Expires = "Unknown"
        $Status = "Unknown"
        $CIDR = "Unknown"
        $Source = "RDAP"
        $Raw = $null

        $RdapSuccess = $false
        
        # Determine RDAP endpoint
        $Url = ""
        if ($Type -eq "IP") {
            $Url = "https://rdap.org/ip/$Indicator"
        } else {
            $Url = "https://rdap.org/domain/$Indicator"
        }

        Write-Verbose "Querying RDAP: $Url"
        try {
            $Headers = @{ "Accept" = "application/rdap+json, application/json" }
            $Raw = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get -TimeoutSec 5 -ErrorAction Stop
            $RdapSuccess = $true
        }
        catch {
            Write-Verbose "RDAP query failed: $_. Falling back to local WHOIS client."
        }

        if ($RdapSuccess -and $Raw) {
            try {
                if ($Type -eq "IP") {
                    # Extract Org Name
                    if ($Raw.name) {
                        $OrgName = $Raw.name
                    }
                    elseif ($Raw.entities) {
                        # Search entities vcard for name
                        foreach ($entity in $Raw.entities) {
                            if ($entity.vcardArray) {
                                $vcard = $entity.vcardArray[1]
                                $fn = $vcard | Where-Object { $_[0] -eq 'fn' } | ForEach-Object { $_[3] } | Select-Object -First 1
                                if ($fn) {
                                    $OrgName = $fn
                                    break
                                }
                            }
                        }
                    }
                    
                    if ($Raw.country) {
                        $Country = $Raw.country
                    }
                    
                    if ($Raw.startAddress -and $Raw.endAddress) {
                        $CIDR = "$($Raw.startAddress) - $($Raw.endAddress)"
                    }
                    
                    if ($Raw.events) {
                        $registration = $Raw.events | Where-Object { $_.eventAction -eq 'registration' } | Select-Object -First 1
                        if ($registration) { $Created = $registration.eventDate }
                    }
                } else {
                    # Domain
                    if ($Raw.entities) {
                        foreach ($entity in $Raw.entities) {
                            if ($entity.roles -contains 'registrar' -and $entity.vcardArray) {
                                $fn = $entity.vcardArray[1] | Where-Object { $_[0] -eq 'fn' } | ForEach-Object { $_[3] } | Select-Object -First 1
                                if ($fn) {
                                    $Registrar = $fn
                                    break
                                }
                            }
                        }
                    }
                    
                    if ($Raw.events) {
                        $registration = $Raw.events | Where-Object { $_.eventAction -eq 'registration' } | Select-Object -First 1
                        if ($registration) { $Created = $registration.eventDate }
                        
                        $expiration = $Raw.events | Where-Object { $_.eventAction -eq 'expiration' } | Select-Object -First 1
                        if ($expiration) { $Expires = $expiration.eventDate }
                    }
                    
                    if ($Raw.status) {
                        $Status = $Raw.status -join ", "
                    }
                }
            } catch {
                Write-Verbose "Error parsing RDAP response fields. Falling back to raw lookup."
            }
        } else {
            # Fallback to local command-line client
            $Source = "CLI WHOIS"
            if (Get-Command whois -ErrorAction SilentlyContinue) {
                Write-Verbose "Executing command: whois $Indicator"
                $RawOutput = whois $Indicator
                if ($RawOutput) {
                    $Raw = $RawOutput -join "`n"
                    
                    # Regex parsing of CLI output
                    if ($Raw -match '(?i)OrgName:\s*(.*)') { $OrgName = $Matches[1].Trim() }
                    elseif ($Raw -match '(?i)Registrant Organization:\s*(.*)') { $OrgName = $Matches[1].Trim() }
                    elseif ($Raw -match '(?i)holder:\s*(.*)') { $OrgName = $Matches[1].Trim() }
                    elseif ($Raw -match '(?i)org:\s*(.*)') { $OrgName = $Matches[1].Trim() }

                    if ($Raw -match '(?i)Country:\s*(.*)') { $Country = $Matches[1].Trim() }
                    
                    if ($Raw -match '(?i)Registrar:\s*(.*)') { $Registrar = $Matches[1].Trim() }
                    
                    if ($Raw -match '(?i)Creation Date:\s*(.*)') { $Created = $Matches[1].Trim() }
                    elseif ($Raw -match '(?i)created:\s*(.*)') { $Created = $Matches[1].Trim() }
                    
                    if ($Raw -match '(?i)Registry Expiry Date:\s*(.*)') { $Expires = $Matches[1].Trim() }
                    elseif ($Raw -match '(?i)paid-till:\s*(.*)') { $Expires = $Matches[1].Trim() }
                    
                    if ($Raw -match '(?i)Status:\s*(.*)') { $Status = $Matches[1].Trim() }
                    
                    if ($Raw -match '(?i)CIDR:\s*(.*)') { $CIDR = $Matches[1].Trim() }
                }
            } else {
                Write-Error "Could not fetch WHOIS details: RDAP lookup failed and local 'whois' tool was not found."
                return
            }
        }

        # Print Visual Card
        Write-Host "`n=== WHOIS/RDAP Information Summary ===" -ForegroundColor Cyan
        Write-Host "Indicator:  $Indicator ($Type)"
        Write-Host "Source:     $Source"
        if ($Type -eq "IP") {
            Write-Host "Org Name:   $OrgName"
            Write-Host "Country:    $Country"
            Write-Host "IP Range:   $CIDR"
            Write-Host "Registered: $Created"
        } else {
            Write-Host "Registrar:  $Registrar"
            Write-Host "Created:    $Created"
            Write-Host "Expires:    $Expires"
            Write-Host "Status:     $Status"
        }
        Write-Host "======================================`n"

        # Return structured object
        return [PSCustomObject]@{
            Indicator = $Indicator
            Type      = $Type
            OrgName   = $OrgName
            Country   = $Country
            Registrar = $Registrar
            Created   = $Created
            Expires   = $Expires
            Status    = $Status
            CIDR      = $CIDR
            Source    = $Source
            RawData   = $Raw
        }
    }
}

# ----------------------------------------------------
# 4. Get-TISummary
# ----------------------------------------------------
function Get-TISummary {
    <#
    .SYNOPSIS
        Provide a comprehensive threat intelligence summary of an indicator.
    .DESCRIPTION
        Combines DNS resolution, GeoIP geolocation, WHOIS registration details,
        VirusTotal detection ratio (if key set), and AlienVault OTX pulses into a single consolidated view.
    .PARAMETER Indicator
        The IP address, domain name, or file hash.
    .EXAMPLE
        Get-TISummary "1.1.1.1"
    .EXAMPLE
        Get-TISummary "badurl.xyz"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Indicator
    )
    process {
        $Indicator = $Indicator.Trim()
        $Type = Get-IndicatorType -Indicator $Indicator
        
        if ($Type -eq "Unknown") {
            Write-Error "Invalid indicator format: '$Indicator'. Must be an IP, Domain, or Hash."
            return
        }

        Write-Host "Aggregating threat intelligence for $Indicator..." -ForegroundColor Cyan

        # Setup variables
        $GeoInfo = $null
        $WhoisInfo = $null
        $VTInfo = $null
        $OTXCount = 0
        $OTXPulses = @()
        $DnsResolution = $null

        # 1. DNS Resolution / Geolocation
        if ($Type -eq "IP") {
            try {
                Write-Verbose "Resolving reverse DNS..."
                $DnsResolution = [System.Net.Dns]::GetHostEntry($Indicator).HostName
            } catch {
                $DnsResolution = "N/A"
            }

            try {
                Write-Verbose "Querying IP Geolocation..."
                # ip-api.com returns clean geo data for IPs
                $GeoInfo = Invoke-RestMethod -Uri "http://ip-api.com/json/$Indicator" -Method Get -TimeoutSec 5
            } catch {
                Write-Verbose "Geolocation query failed."
            }
        }
        elseif ($Type -eq "Domain") {
            try {
                Write-Verbose "Resolving domain IP addresses..."
                $DnsResolution = [System.Net.Dns]::GetHostAddresses($Indicator) | ForEach-Object { $_.IPAddressToString }
            } catch {
                $DnsResolution = @()
            }
        }

        # 2. WHOIS
        if ($Type -eq "IP" -or $Type -eq "Domain") {
            Write-Verbose "Performing WHOIS query..."
            $WhoisInfo = Get-whois -Indicator $Indicator -ErrorAction SilentlyContinue
        }

        # 3. VirusTotal (If API Key is set)
        $ApiKey = $env:VIRUSTOTAL_API_KEY
        if (-not $ApiKey) {
            $Config = Get-SOCMoxConfig
            if ($Config -and $Config.VT_API_Key) {
                $ApiKey = $Config.VT_API_Key
            }
        }

        if ($ApiKey) {
            Write-Verbose "Performing VirusTotal lookup..."
            $VTInfo = Get-VTlookup -Indicator $Indicator -ApiKey $ApiKey -ErrorAction SilentlyContinue
        }

        # 4. AlienVault OTX
        $OtxUrl = ""
        switch ($Type) {
            "IP" { $OtxUrl = "https://otx.alienvault.com/api/v1/indicators/IPv4/$Indicator/general" }
            "Domain" { $OtxUrl = "https://otx.alienvault.com/api/v1/indicators/domain/$Indicator/general" }
            "Hash" { $OtxUrl = "https://otx.alienvault.com/api/v1/indicators/file/$Indicator/general" }
        }

        if ($OtxUrl) {
            try {
                Write-Verbose "Querying AlienVault OTX..."
                $OtxRes = Invoke-RestMethod -Uri $OtxUrl -Method Get -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($OtxRes -and $OtxRes.pulse_info) {
                    $OTXCount = $OtxRes.pulse_info.count
                    if ($OtxRes.pulse_info.pulses) {
                        $OTXPulses = $OtxRes.pulse_info.pulses | Select-Object -First 3 | ForEach-Object { $_.name }
                    }
                }
            } catch {
                Write-Verbose "AlienVault OTX lookup failed."
            }
        }

        # Calculate Threat Level
        $Score = 0
        $DetectionsStr = "None"
        
        if ($VTInfo -and $VTInfo.Malicious -gt 0) {
            $VTCount = $VTInfo.Malicious
            $TotalEngines = $VTInfo.Malicious + $VTInfo.Suspicious + $VTInfo.Harmless + $VTInfo.Undetected
            $Ratio = $VTCount / $TotalEngines
            $Score += [Math]::Min(100, [Math]::Round($Ratio * 100))
            $DetectionsStr = "$VTCount engine(s) flagged malicious on VirusTotal"
        }
        
        if ($OTXCount -gt 0) {
            $Score += [Math]::Min(50, $OTXCount * 10)
        }

        $ThreatLevel = "Info / Safe"
        $Color = "Green"
        if ($Score -ge 50) {
            $ThreatLevel = "High / Malicious"
            $Color = "Red"
        }
        elseif ($Score -gt 0) {
            $ThreatLevel = "Medium / Suspicious"
            $Color = "Yellow"
        }

        # Format beautiful terminal layout
        Write-Host "`n┌────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "│                THREAT INTEL SUMMARY                    │" -ForegroundColor Cyan
        Write-Host "└────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host "  Indicator:    $Indicator ($Type)"
        Write-Host "  Threat Level: $ThreatLevel" -ForegroundColor $Color
        Write-Host "  Threat Score: $Score / 100" -ForegroundColor $Color
        
        if ($DetectionsStr -ne "None") {
            Write-Host "  Detections:   $DetectionsStr" -ForegroundColor Red
        }

        if ($Type -eq "IP") {
            if ($GeoInfo -and $GeoInfo.status -eq "success") {
                Write-Host "  Location:     $($GeoInfo.city), $($GeoInfo.regionName), $($GeoInfo.country)"
                Write-Host "  ISP / Org:    $($GeoInfo.isp) / $($GeoInfo.org)"
                Write-Host "  ASN:          $($GeoInfo.as)"
            }
            Write-Host "  Reverse DNS:  $DnsResolution"
        }
        elseif ($Type -eq "Domain") {
            if ($DnsResolution) {
                $IPList = $DnsResolution -join ", "
                Write-Host "  IP Addresses: $IPList"
            }
        }

        if ($WhoisInfo) {
            if ($Type -eq "IP") {
                Write-Host "  Net Owner:    $($WhoisInfo.OrgName) ($($WhoisInfo.Country))"
                if ($WhoisInfo.CIDR -and $WhoisInfo.CIDR -ne "Unknown") {
                    Write-Host "  CIDR Range:   $($WhoisInfo.CIDR)"
                }
            } else {
                Write-Host "  Registrar:    $($WhoisInfo.Registrar)"
                Write-Host "  Registered:   $($WhoisInfo.Created)"
                Write-Host "  Expires:      $($WhoisInfo.Expires)"
            }
        }

        if ($OTXCount -gt 0) {
            Write-Host "  OTX Pulses:   Found in $OTXCount threat pulse(s)" -ForegroundColor Yellow
            foreach ($Pulse in $OTXPulses) {
                Write-Host "                - $Pulse" -ForegroundColor DarkGray
            }
        }

        if ($VTInfo) {
            Write-Host "  VT Link:      $($VTInfo.ReportUrl)" -ForegroundColor DarkCyan
        }
        Write-Host "──────────────────────────────────────────────────────────`n"

        # Return structured object
        return [PSCustomObject]@{
            Indicator     = $Indicator
            Type          = $Type
            ThreatLevel   = $ThreatLevel
            ThreatScore   = $Score
            DnsRecord     = $DnsResolution
            GeoInfo       = $GeoInfo
            WhoisDetails  = $WhoisInfo
            OTXPulseCount = $OTXCount
            OTXPulses     = $OTXPulses
            VTDetails     = $VTInfo
        }
    }
}

# ----------------------------------------------------
# 5. Get-News
# ----------------------------------------------------
function Get-News {
    <#
    .SYNOPSIS
        Fetch the latest security news from Bleeping Computer.
    .DESCRIPTION
        Queries Bleeping Computer's RSS feed and formats the top news articles in the terminal.
    .PARAMETER Count
        The number of news articles to retrieve (default is 5).
    .EXAMPLE
        Get-News
    .EXAMPLE
        Get-News -Count 10
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [int]$Count = 5
    )
    process {
        Write-Host "Fetching the latest security news from Bleeping Computer..." -ForegroundColor Cyan
        $FeedUrl = "https://www.bleepingcomputer.com/feed/"
        try {
            $Items = Invoke-RestMethod -Uri $FeedUrl -TimeoutSec 10
            
            # Select the top N items
            $TopItems = $Items | Select-Object -First $Count
            
            Write-Host "`n=== Latest Security News ===" -ForegroundColor Cyan
            $Index = 1
            $OutList = @()
            foreach ($Item in $TopItems) {
                $Title = $Item.title.Trim()
                $Link = $Item.link.Trim()
                $PubDate = $Item.pubDate
                
                Write-Host "[$Index] $Title" -ForegroundColor Green
                Write-Host "    Published: $PubDate" -ForegroundColor Gray
                Write-Host "    Link:      $Link" -ForegroundColor DarkCyan
                Write-Host ""
                
                $OutList += [PSCustomObject]@{
                    Index     = $Index
                    Title     = $Title
                    Link      = $Link
                    Published = $PubDate
                }
                $Index++
            }
            Write-Host "============================`n"
            return $OutList
        } catch {
            Write-Error "Failed to fetch news from Bleeping Computer: $_"
        }
    }
}

# ----------------------------------------------------
# 6. Get-CVEDetails
# ----------------------------------------------------
function Get-CVEDetails {
    <#
    .SYNOPSIS
        Retrieve details for a specific CVE from the NIST NVD database.
    .DESCRIPTION
        Queries the NIST NVD API v2 for CVE information, CVSS scores, descriptions,
        and CISA Known Exploited Vulnerabilities (KEV) status.
    .PARAMETER CVE
        The CVE identifier. Can be the full ID (e.g. CVE-2023-38606), 
        with or without the CVE prefix (e.g. 2023-38606), or just the digits (e.g. 202338606).
    .EXAMPLE
        Get-CVEDetails "CVE-2023-38606"
    .EXAMPLE
        Get-CVEDetails "2023-38606"
    .EXAMPLE
        Get-CVEDetails "202338606"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$CVE
    )
    process {
        # Normalize input
        $Cleaned = $CVE.Trim() -replace '(?i)^cve-?', ''
        
        $CveId = ""
        if ($Cleaned -match '^(\d{4})-(\d{4,7})$') {
            $CveId = "CVE-$($Matches[1])-$($Matches[2])"
        }
        elseif ($Cleaned -match '^(\d{4})(\d{4,7})$') {
            $CveId = "CVE-$($Matches[1])-$($Matches[2])"
        }
        else {
            Write-Error "Invalid CVE format: '$CVE'. Please use formats like 'CVE-YYYY-NNNN', 'YYYY-NNNN', or 'YYYYNNNN'."
            return
        }

        Write-Host "Querying NIST NVD for details on $CveId..." -ForegroundColor Cyan
        $Url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CveId"

        try {
            $Response = Invoke-RestMethod -Uri $Url -TimeoutSec 15
            
            if ($Response.totalResults -eq 0 -or -not $Response.vulnerabilities) {
                Write-Warning "No details found for $CveId in the NIST NVD."
                return
            }

            $CveData = $Response.vulnerabilities[0].cve
            
            # Parse CVSS Metrics
            $CvssScore = "N/A"
            $CvssSeverity = "N/A"
            $CvssVector = "N/A"
            $CvssVersion = "N/A"

            $Metrics = $CveData.metrics
            if ($Metrics) {
                if ($Metrics.cvssMetricV31) {
                    $Metric = $Metrics.cvssMetricV31[0]
                    $CvssScore = $Metric.cvssData.baseScore
                    $CvssSeverity = $Metric.cvssData.baseSeverity
                    $CvssVector = $Metric.cvssData.vectorString
                    $CvssVersion = "3.1"
                }
                elseif ($Metrics.cvssMetricV30) {
                    $Metric = $Metrics.cvssMetricV30[0]
                    $CvssScore = $Metric.cvssData.baseScore
                    $CvssSeverity = $Metric.cvssData.baseSeverity
                    $CvssVector = $Metric.cvssData.vectorString
                    $CvssVersion = "3.0"
                }
                elseif ($Metrics.cvssMetricV2) {
                    $Metric = $Metrics.cvssMetricV2[0]
                    $CvssScore = $Metric.cvssData.baseScore
                    $CvssSeverity = $Metric.cvssData.baseSeverity
                    $CvssVector = $Metric.cvssData.vectorString
                    $CvssVersion = "2.0"
                }
            }

            # Parse Description
            $Description = $CveData.descriptions | Where-Object { $_.lang -eq 'en' } | ForEach-Object { $_.value } | Select-Object -First 1

            # Parse CISA KEV Details
            $IsKnownExploited = $false
            if ($CveData.cisaExploitAdd) {
                $IsKnownExploited = $true
            }

            # Formatting outputs beautifully
            Write-Host "`n┌────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
            Write-Host "│                   CVE DETAILS                          │" -ForegroundColor Cyan
            Write-Host "└────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
            Write-Host "  CVE ID:       $CveId" -ForegroundColor Yellow
            Write-Host "  Status:       $($CveData.vulnStatus)"
            Write-Host "  Published:    $($CveData.published)"
            
            # Severity color coding
            $SevColor = "Gray"
            if ($CvssSeverity -eq "CRITICAL") { $SevColor = "Red" }
            elseif ($CvssSeverity -eq "HIGH") { $SevColor = "Red" }
            elseif ($CvssSeverity -eq "MEDIUM") { $SevColor = "Yellow" }
            elseif ($CvssSeverity -eq "LOW") { $SevColor = "Green" }
            
            Write-Host "  CVSS Score:   $CvssScore ($CvssSeverity) [v$CvssVersion]" -ForegroundColor $SevColor
            Write-Host "  CVSS Vector:  $CvssVector"
            
            if ($IsKnownExploited) {
                Write-Host ""
                Write-Host "  ⚠️  CISA KEV ALERT: KNOWN EXPLOITED VULNERABILITY" -ForegroundColor Red
                Write-Host "  Added to KEV: $($CveData.cisaExploitAdd)" -ForegroundColor Red
                Write-Host "  Required Due: $($CveData.cisaActionDue)" -ForegroundColor Red
                Write-Host "  Name:         $($CveData.cisaVulnerabilityName)" -ForegroundColor DarkRed
            }
            
            Write-Host ""
            Write-Host "  Description:" -ForegroundColor Cyan
            # Format text wrap for description
            $DescLines = $Description -split "\n"
            foreach ($Line in $DescLines) {
                Write-Host "    $Line"
            }
            Write-Host ""
            Write-Host "  NVD Link:     https://nvd.nist.gov/vuln/detail/$CveId" -ForegroundColor DarkCyan
            Write-Host "──────────────────────────────────────────────────────────`n"

            # Return object
            return [PSCustomObject]@{
                CVEId            = $CveId
                Published        = $CveData.published
                CVSSScore        = $CvssScore
                CVSSSeverity     = $CvssSeverity
                CVSSVector       = $CvssVector
                Description      = $Description
                IsKnownExploited = $IsKnownExploited
                CisaDetails      = if ($IsKnownExploited) {
                    @{
                        ExploitAdd = $CveData.cisaExploitAdd
                        ActionDue  = $CveData.cisaActionDue
                        Name       = $CveData.cisaVulnerabilityName
                        Action     = $CveData.cisaRequiredAction
                    }
                } else { $null }
                RawData          = $CveData
            }
        }
        catch {
            Write-Error "Failed to query NIST NVD: $_"
        }
    }
}

# ----------------------------------------------------
# 7. Get-GeoIP
# ----------------------------------------------------
function Get-GeoIP {
    <#
    .SYNOPSIS
        Get geographical and network details for an IP address or domain.
    .DESCRIPTION
        Queries ip-api.com to retrieve location, ISP, organization, and AS info.
        If a domain name is provided, it automatically resolves to its IP address first.
    .PARAMETER Indicator
        The IP address or domain name to locate.
    .EXAMPLE
        Get-GeoIP "8.8.8.8"
    .EXAMPLE
        Get-GeoIP "google.com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Indicator
    )
    process {
        $Clean = $Indicator.Trim()
        $Type = Get-IndicatorType -Indicator $Clean
        
        $TargetIp = $Clean
        if ($Type -eq "Domain") {
            Write-Verbose "Resolving domain '$Clean'..."
            try {
                $IPs = [System.Net.Dns]::GetHostAddresses($Clean) | ForEach-Object { $_.IPAddressToString }
                if ($IPs) {
                    $TargetIp = $IPs[0]
                    Write-Host "Resolved '$Clean' to IP: $TargetIp" -ForegroundColor Gray
                }
            } catch {
                Write-Error "Failed to resolve domain '$Clean': $_"
                return
            }
        }
        elseif ($Type -ne "IP") {
            Write-Error "Invalid IP or domain indicator: '$Clean'."
            return
        }

        Write-Host "Retrieving Geolocation for $TargetIp..." -ForegroundColor Cyan
        $Url = "http://ip-api.com/json/$TargetIp"

        try {
            $Geo = Invoke-RestMethod -Uri $Url -TimeoutSec 10
            
            if ($Geo.status -ne "success") {
                Write-Warning "Failed to query IP geolocation: $($Geo.message)"
                return
            }

            # Print beautiful summary card
            Write-Host "`n┌────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
            Write-Host "│                   GEOLOCATION DETAILS                  │" -ForegroundColor Cyan
            Write-Host "└────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
            Write-Host "  Query Target: $Clean" -ForegroundColor Yellow
            if ($Clean -ne $TargetIp) {
                Write-Host "  Target IP:    $TargetIp"
            }
            Write-Host "  Country:      $($Geo.country) ($($Geo.countryCode))"
            Write-Host "  Region/State: $($Geo.regionName) ($($Geo.region))"
            Write-Host "  City / Zip:   $($Geo.city) / $($Geo.zip)"
            Write-Host "  Coordinates:  Lat: $($Geo.lat), Lon: $($Geo.lon)"
            Write-Host "  Timezone:     $($Geo.timezone)"
            Write-Host "  ISP / Org:    $($Geo.isp) / $($Geo.org)"
            Write-Host "  ASN / Owner:  $($Geo.as)"
            Write-Host "──────────────────────────────────────────────────────────`n"

            # Return object
            return [PSCustomObject]@{
                Query        = $Clean
                ResolvedIP   = $TargetIp
                Country      = $Geo.country
                CountryCode  = $Geo.countryCode
                Region       = $Geo.regionName
                City         = $Geo.city
                Zip          = $Geo.zip
                Latitude     = $Geo.lat
                Longitude    = $Geo.lon
                Timezone     = $Geo.timezone
                ISP          = $Geo.isp
                Org          = $Geo.org
                ASN          = $Geo.as
                RawData      = $Geo
            }
        } catch {
            Write-Error "Failed to retrieve Geolocation details: $_"
        }
    }
}

# ----------------------------------------------------
# 8. New-TriagePrompt
# ----------------------------------------------------
function New-TriagePrompt {
    <#
    .SYNOPSIS
        Interactively generate a standardized XML security triage prompt for LLMs.
    .DESCRIPTION
        Prompts the analyst for alert metadata, host context, user context, and raw telemetry,
        generates an structured XML triage template, and copies it to the system clipboard.
    .EXAMPLE
        New-TriagePrompt
    #>
    [CmdletBinding()]
    param()
    process {
        Clear-Host
        Write-Host "=== LLM Triage Prompt Generator ===" -ForegroundColor Cyan
        Write-Host "Press Enter to skip any fields you don't have.`n"

        # 1. Alert Metadata
        Write-Host "[1/4] Alert Metadata" -ForegroundColor Yellow
        $alertName = Read-Host "Alert name"
        $alertSource = Read-Host "Alert Source (e.g., EDR/Firewall/SIEM)"
        $otherAlerts = Read-Host "Other alerts?"

        # 2. Host Entity Context
        Write-Host "`n[2/4] Host Entity Context/Location" -ForegroundColor Yellow
        $hostOS = Read-Host "Host OS"
        $hostCriticality = Read-Host "Host criticality (e.g., Tier 0, Workstation)"
        $hostLocation = Read-Host "Host location (e.g., On-prem/Cloud)"

        # 3. User Entity
        Write-Host "`n[3/4] User Entity/Location" -ForegroundColor Yellow
        $userRole = Read-Host "What is this user's role?"
        $sourceIp = Read-Host "Is there a source IP for this detection?"

        # 4. Raw Telemetry
        Write-Host "`n[4/4] Raw Telemetry" -ForegroundColor Yellow
        $uploadLog = Read-Host "Will a log or file be uploaded directly to the AI separately? (Y/N)"

        $rawTelemetry = ""

        if ($uploadLog -match "^[Nn]") {
            Write-Host "Paste the raw log or context below. (Press Enter on an empty line when finished):" -ForegroundColor DarkGray
            
            # Allows for multi-line pasting (crucial for JSON logs)
            $rawTelemetryText = @()
            while ($true) {
                $line = Read-Host
                if ([string]::IsNullOrWhiteSpace($line)) { break }
                $rawTelemetryText += $line
            }
            $rawTelemetry = $rawTelemetryText -join "`n"
        } else {
            $rawTelemetry = "[Review the attached file for raw telemetry]"
        }

        # Construct the XML Template
        $xmlPrompt = @"
<instructions>
You are an expert Security Operations Analyst. Review the following alert context and determine the likelihood of a true positive compromise.

Perform the following actions:
1. Analyze the alert context and raw telemetry.
2. Determine if this activity is malicious, benign administrative behavior, or a false positive. Provide a brief justification.
3. Extract any key Indicators of Compromise (IoCs).
4. Recommend immediate next steps for containment or investigation.
</instructions>

<alert_metadata>
Alert Name: $alertName
Alert Source: $alertSource
Related Alerts: $otherAlerts
</alert_metadata>

<host_entity_context>
Host OS: $hostOS
Host Criticality: $hostCriticality
Host Location: $hostLocation
</host_entity_context>

<user_entity_context>
User Role: $userRole
Source IP: $sourceIp
</user_entity_context>

<raw_telemetry>
$rawTelemetry
</raw_telemetry>
"@

        # Copy to clipboard
        try {
            $xmlPrompt | Set-Clipboard -ErrorAction Stop
            Write-Host "`n[+] Success! The XML prompt has been generated and copied to your clipboard." -ForegroundColor Green
            Write-Host "You can now paste it directly into your AI tool.`n"
        } catch {
            Write-Warning "Could not copy to clipboard automatically: $_"
            Write-Host "`nGenerated Prompt (you can copy manually):" -ForegroundColor Cyan
            Write-Host $xmlPrompt
        }
        
        return $xmlPrompt
    }
}

# ----------------------------------------------------
# 9. Get-CloudStatus
# ----------------------------------------------------
function Get-CloudStatus {
    <#
    .SYNOPSIS
    Queries the public status feeds for AWS, Azure, and Google Cloud.
    #>
    [CmdletBinding()]
    param()
    process {
        Write-Host "`n☁️  Multi-Cloud Status Check (AWS, Azure, GCP)" -ForegroundColor Cyan
        Write-Host "==============================================" -ForegroundColor Cyan
        
        # [1] Amazon Web Services (AWS) - RSS Feed
        try {
            $awsReq = Invoke-WebRequest -Uri "https://status.aws.amazon.com/rss/all.rss" -UseBasicParsing -ErrorAction Stop
            [xml]$awsXml = $awsReq.Content
            $awsItems = $awsXml.SelectNodes("//item") | Select-Object -First 3
            
            Write-Host "`nAmazon Web Services (AWS)" -ForegroundColor Yellow
            if ($awsItems) {
                foreach ($item in $awsItems) {
                    $title = if ($item.title -is [System.Xml.XmlNode]) { $item.title.InnerText } else { $item.title }
                    $pubDate = if ($item.pubDate -is [System.Xml.XmlNode]) { $item.pubDate.InnerText } else { $item.pubDate }
                    Write-Host " 🔸 $title"
                    Write-Host "    Date: $pubDate" -ForegroundColor DarkGray
                }
            } else {
                Write-Host " 🔹 No recent widespread events reported." -ForegroundColor Green
            }
        } catch {
            Write-Host " ❌ Failed to fetch AWS Status. Error: $_" -ForegroundColor Red
        }

        # [2] Microsoft Azure - RSS Feed
        try {
            $azureReq = Invoke-WebRequest -Uri "https://azurestatuscdn.azureedge.net/en-us/status/feed/" -UseBasicParsing -ErrorAction Stop
            [xml]$azureXml = $azureReq.Content
            $azureItems = $azureXml.SelectNodes("//item") | Select-Object -First 3
            
            Write-Host "`nMicrosoft Azure" -ForegroundColor Blue
            if ($azureItems) {
                foreach ($item in $azureItems) {
                    $title = if ($item.title -is [System.Xml.XmlNode]) { $item.title.InnerText } else { $item.title }
                    $pubDate = if ($item.pubDate -is [System.Xml.XmlNode]) { $item.pubDate.InnerText } else { $item.pubDate }
                    Write-Host " 🔸 $title"
                    Write-Host "    Date: $pubDate" -ForegroundColor DarkGray
                }
            } else {
                 Write-Host " 🔹 No active widespread events in the RSS feed." -ForegroundColor Green
            }
        } catch {
            Write-Host " ❌ Failed to fetch Azure Status. Error: $_" -ForegroundColor Red
        }

        # [3] Google Cloud Platform (GCP) - JSON Feed
        try {
            # GCP returns a clean JSON array of recent incidents, so we can use Invoke-RestMethod directly
            $gcpData = Invoke-RestMethod -Uri "https://status.cloud.google.com/incidents.json" -ErrorAction Stop
            $gcpItems = $gcpData | Select-Object -First 3
            
            Write-Host "`nGoogle Cloud Platform (GCP)" -ForegroundColor Green
            if ($gcpItems) {
                foreach ($item in $gcpItems) {
                    Write-Host " 🔸 $($item.external_desc)"
                    Write-Host "    Status: $($item.status) | Started: $($item.begin)" -ForegroundColor DarkGray
                }
            } else {
                Write-Host " 🔹 No recent incidents reported." -ForegroundColor Green
            }
        } catch {
            Write-Host " ❌ Failed to fetch GCP Status. Error: $_" -ForegroundColor Red
        }
        
        Write-Host "`n==============================================" -ForegroundColor Cyan
    }
}





