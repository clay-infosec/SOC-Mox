<pre>
 \     __   ____    /     ___  ___   ___  
  \  / //\_ \ \ \  /     / __|/ _ \ / __| 
    / />  <  \ \ \       \__ \ (_) | (__  
   /_/_ \/    \_\_\      |___/\___/_\___|_   __
   \ \ \    _/\_/ /          |  \/  |/ _ \ \/ /
    \ \ \   >  < /           | |\/| | (_) >  <  
     \_\_\   \/_/            |_|  |_|\___/_/\_\
    </pre>
          

# SOC MOX 💎

SOC MOX is a PowerShell module and profile  specifically tailored for **Security Operations Center Analysts** to rapidly triage and investigate IOCs and other issues.

<img width="648" height="632" alt="image" src="https://github.com/user-attachments/assets/9d9e871c-bade-49a3-80b6-b5bfab22b279" />

---

## Features

- **VirusTotal Integration (`Get-VTlookup`)**: Instantly query IPs, Domains, and Hashes against VirusTotal's API for detections.
- **WHOIS/RDAP (`Get-whois`)**: Automatically queries RDAP for JSON structured WHOIS metadata
- **Threat Intel Aggregator (`Get-TISummary`)**: An orchestrated dashboard that performs reverse DNS, Geo-IP classification, WHOIS lookup, AlienVault OTX pulses, and VirusTotal detections in a single command.
- **Security News (`Get-News`)**: Fetches the top security articles from Bleeping Computer directly to your console.
- **CVE Details (`Get-CVEDetails`)**: Queries the NIST NVD API for detailed information, CVSS scoring, descriptions, and CISA KEV status of any CVE.
- **IP Geolocation (`Get-GeoIP`)**: Retreives geographical details and ISP/ASN routing information for any IP or domain name.
- **AI Triage Prompt (`New-TriagePrompt`)**: An interactive terminal-based wizard that generates a structured XML threat triage prompt and automatically copies it to the system clipboard for immediate use with LLMs.
- **Cloud Status (`Get-CloudStatus`)**: Queries the public RSS/JSON status feeds for AWS, Azure, and Google Cloud to report active outages.

<img width="1377" height="568" alt="image" src="https://github.com/user-attachments/assets/0eab3c12-053a-47e0-833f-530e3a65ca0d" />


---

## Directory Structure

```text
soc-mox/
├── Microsoft.PowerShell_profile.ps1     # Core profile script (loads banner & module)
├── README.md                            # Documentation and setup instructions
└── SOCMox/
    ├── SOCMox.psd1                      # Module Manifest
    └── SOCMox.psm1                      # Core Cmdlets logic
```

---

## Installation & Setup

To load **SOC MOX** automatically every time you start PowerShell, you can configure your PowerShell profile:

1. Locate your PowerShell profile path by running:
   ```powershell
   $PROFILE
   ```
2. Open or create that file, and dot-source the `Microsoft.PowerShell_profile.ps1` file:
3. In your powershell prifile add a "." followed by the location of the MOXLoader file, example:

```powershell
   . "/Users/ME/Tools/MOXloader.ps1"
   ```

4. Restart PowerShell or reload your profile:
   ```powershell
   . $PROFILE
   ```

---

## Configuration

To use VirusTotal features, you should configure your API key. You can register for a free key on [VirusTotal](https://www.virustotal.com).

Save the key permanently so it loads automatically on every session:
```powershell
Set-VTApiKey -Key "YOUR_VIRUSTOTAL_API_KEY"
```
---

## Usage Examples

### 1. Threat Intel Summary
Get a consolidated dashboard of an IP address, domain name, or file hash:
```powershell
Get-TISummary -Indicator "8.8.8.8"
Get-TISummary "malicious-domain.xyz"
Get-TISummary "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

### 2. WHOIS / RDAP lookup
Fetch registrar details, network ranges, and registration dates:
```powershell
Get-whois "google.com"
```

### 3. VirusTotal Lookup
Look up detection statistics:
```powershell
Get-VTlookup "1.1.1.1"
```

### 4. Fetch Security News
Get the top 5 cybersecurity news articles from Bleeping Computer:
```powershell
Get-News
# Or fetch the top 10 articles
Get-News -Count 10
```

### 5. NIST CVE Lookup
Fetch detailed data, CVSS metrics, and CISA KEV status for a CVE:
```powershell
Get-CVEDetails "CVE-2023-38606"
# Shortcuts with digits or partial strings work too:
Get-CVEDetails "2023-38606"
Get-CVEDetails "202338606"
```

### 6. Geolocation Lookup
Look up the geological and ISP details of an IP address or domain name:
```powershell
Get-GeoIP "8.8.8.8"
Get-GeoIP "google.com"
```

### 7. AI Triage Prompt Wizard
Launch the interactive wizard to generate an XML triage prompt for LLMs (copies to clipboard automatically):
```powershell
New-TriagePrompt
```

### 8. Cloud Outage Status Check
Check for recent or ongoing outages across AWS, Azure, and Google Cloud:
```powershell
Get-CloudStatus
```
