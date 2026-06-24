# SOC MOX PowerShell Profile Startup Script
# Loads the SOCMox module, prints the banner, and displays the command interface.

# 1. Determine script directory and load module
$ModulePath = Join-Path $PSScriptRoot "SOCMox/SOCMox.psd1"
if (Test-Path $ModulePath) {
    try {
        Import-Module $ModulePath -Force
    } catch {
        Write-Warning "Failed to load SOCMox module: $_"
    }
} else {
    Write-Warning "SOCMox module not found at: $ModulePath"
}

# 2. Display the SOC MOX ASCII Art Banner
Write-Host " \     __   ____    /     ___  ___   ___  " -ForegroundColor Cyan
Write-Host "  \  / //\_ \ \ \  /     / __|/ _ \ / __| " -ForegroundColor Cyan
Write-Host "    / />  <  \ \ \       \__ \ (_) | (__  " -ForegroundColor Cyan
Write-Host "   /_/_ \/    \_\_\      |___/\___/_\___|_   __" -ForegroundColor Cyan
Write-Host "   \ \ \    _/\_/ /          |  \/  |/ _ \ \/ /" -ForegroundColor Cyan
Write-Host "    \ \ \   >  < /           | |\/| | (_) >  <  " -ForegroundColor Cyan
Write-Host "     \_\_\   \/_/            |_|  |_|\___/_/\_\ " -ForegroundColor Cyan
Write-Host ""

# 3. Display loaded tools
Write-Host "================== SOC MOX Loaded ==================" -ForegroundColor DarkCyan
Write-Host "  Virus Total Lookup   : " -NoNewline
Write-Host "Get-VTlookup" -ForegroundColor Green
Write-Host "  Threat Intel Summary : " -NoNewline
Write-Host "Get-TISummary" -ForegroundColor Green
Write-Host "  WhoIs Lookup         : " -NoNewline
Write-Host "Get-whois" -ForegroundColor Green
Write-Host "  Security News Feed   : " -NoNewline
Write-Host "Get-News" -ForegroundColor Green
Write-Host "  NIST CVE Lookup      : " -NoNewline
Write-Host "Get-CVEDetails" -ForegroundColor Green
Write-Host "  IP Geolocation       : " -NoNewline
Write-Host "Get-GeoIP" -ForegroundColor Green
Write-Host "  AI Triage Prompt     : " -NoNewline
Write-Host "New-TriagePrompt" -ForegroundColor Green
Write-Host "  Cloud Outage Status  : " -NoNewline
Write-Host "Get-CloudStatus" -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor DarkCyan
Write-Host "  Config: Set VirusTotal API key with " -NoNewline
Write-Host "Set-VTApiKey" -ForegroundColor Yellow
Write-Host ""
