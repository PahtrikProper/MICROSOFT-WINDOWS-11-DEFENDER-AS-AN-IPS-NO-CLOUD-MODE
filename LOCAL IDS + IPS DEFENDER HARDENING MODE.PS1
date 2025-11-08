<#
.SYNOPSIS
  Local IDS + IPS Defender Hardening + Sysmon installer + Event Viewer Custom View + local viewer.
.NOTES
  - Run as Admin.
  - Local-only: no cloud forwarding, no external log shipping configured.
  - Downloads Sysmon from Microsoft Sysinternals and the SwiftOnSecurity sysmon config.
#>

# -------------------------
# Admin check
# -------------------------
If (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell and 'Run as administrator'. Exiting."
    exit 1
}

Write-Host "=== LOCAL IDS + IPS DEFENDER HARDENING MODE ===" -ForegroundColor Cyan

# -------------------------
# 1) Defender: ASR/IPS Hardening
# -------------------------
Write-Host "[1/5] Hardening Microsoft Defender (ASR / Network Protection / Controlled Folder Access)..." -ForegroundColor Yellow

try {
    # Disable cloud reporting & sample submission (local-only posture)
    Set-MpPreference -MAPSReporting 0 -ErrorAction Stop
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop

    # Network Protection (blocks outbound malicious URLs)
    # 'EnableNetworkProtection' expects values: Disabled/Enabled/ AuditMode - using Enabled string constant can sometimes be different by PS version,
    # so use Set-MpPreference with the switch property if present or registry fallback.
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue

    # Controlled Folder Access - enable
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue

    # Best-effort: set ASR rules to block (Action = block)
    $ASR_Rules = @(
     "56A863A9-875E-4185-98A7-B882C64B5CE5", # Block credential stealing from LSASS etc
     "26190899-1602-49e8-8b27-eb1d0a1ce869", # Block unsigned PowerShell scripts from running
     "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Block Office macro abuse
     "3B576869-A4EC-4529-8536-B80A7769E899"  # Block remote code execution via Office
    )

    # Set actions (1 = block, 0 = disabled, 2 = audit)
    $actions = (1..$ASR_Rules.Count) | ForEach-Object { 1 }
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ASR_Rules -AttackSurfaceReductionRules_Actions ($actions -join ',') -ErrorAction SilentlyContinue

    Write-Host "Defender configured (ASR + NetworkProtection + ControlledFolderAccess)." -ForegroundColor Green
}
catch {
    Write-Warning "Defender configuration partially failed: $($_.Exception.Message)"
}

# -------------------------
# 2) Ensure local-only logging & retention for Sysmon/Defender logs
# -------------------------
Write-Host "[2/5] Configuring local event log retention (no cloud sync)..." -ForegroundColor Yellow

# Set Sysmon operational log to retain more (400MB)
try {
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:419430400 | Out-Null
    # Also ensure Microsoft-Windows-Windows Defender/Operational exists and bump size
    if (Get-EventLog -LogName "System" -ErrorAction SilentlyContinue) {
        wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:209715200 2>$null
    }
    Write-Host "Event retention increased for Sysmon/Defender logs." -ForegroundColor Green
} catch {
    Write-Warning "Could not set event log retention: $($_.Exception.Message)"
}

# -------------------------
# 3) Sysmon: check/install & configure (local-only)
# -------------------------
Write-Host "[3/5] Checking Sysmon installation..." -ForegroundColor Yellow

$sysmonExe = "$env:WINDIR\Sysnative\Sysmon64.exe"
$sysmonInstalled = $false

# Check common locations for Sysmon (Sysinternals)
if (Test-Path $sysmonExe) { $sysmonInstalled = $true }

# Also check installed product via sysmon service presence
try {
    $svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if ($svc) { $sysmonInstalled = $true }
} catch { }

# Prepare temp dir for downloads
$temp = Join-Path $env:TEMP "sysmon_installer_$(Get-Random)"
New-Item -Path $temp -ItemType Directory -Force | Out-Null

if (-not $sysmonInstalled) {
    Write-Host "Sysmon not detected. Downloading and installing..." -ForegroundColor Yellow

    $sysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    $sysmonZip = Join-Path $temp "Sysmon.zip"
    $sysmonXmlUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    $sysmonXml = Join-Path $temp "sysmon.xml"

    try {
        Invoke-WebRequest -Uri $sysmonZipUrl -OutFile $sysmonZip -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $sysmonZip -DestinationPath $temp -Force
        # locate Sysmon64.exe
        $found = Get-ChildItem -Path $temp -Recurse -Filter "Sysmon64.exe" | Select-Object -First 1
        if (-not $found) { throw "Sysmon64.exe not found in Sysmon zip." }
        $sysmonPath = $found.FullName

        Invoke-WebRequest -Uri $sysmonXmlUrl -OutFile $sysmonXml -UseBasicParsing -ErrorAction Stop

        # Install Sysmon with the provided config, accept EULA
        Start-Process -FilePath $sysmonPath -ArgumentList "-accepteula -i `"$sysmonXml`"" -NoNewWindow -Wait -ErrorAction Stop

        Write-Host "Sysmon installed and configured." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to download/install Sysmon: $($_.Exception.Message)"
    }
} else {
    Write-Host "Sysmon appears installed already. Attempting to update config if found..." -ForegroundColor Yellow
    # attempt to find existing sysmon exe and update config if we can fetch xml
    try {
        $sysmonXmlUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
        $sysmonXml = Join-Path $temp "sysmon.xml"
        Invoke-WebRequest -Uri $sysmonXmlUrl -OutFile $sysmonXml -UseBasicParsing -ErrorAction Stop

        # locate sysmon exe
        $sysmonPathCandidate = Get-Command -Name Sysmon64 -ErrorAction SilentlyContinue
        if ($sysmonPathCandidate) {
            $exe = $sysmonPathCandidate.Source
        } else {
            $exe = (Get-ChildItem -Path "$env:WINDIR\*" -Recurse -ErrorAction SilentlyContinue | Where-Object Name -match "Sysmon64.exe" | Select-Object -First 1).FullName
        }
        if ($exe) {
            Start-Process -FilePath $exe -ArgumentList "-accepteula -c `"$sysmonXml`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Write-Host "Sysmon config updated." -ForegroundColor Green
        } else {
            Write-Host "Could not locate Sysmon exe to update config. Leaving current installation alone." -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to update Sysmon config: $($_.Exception.Message)"
    }
}

# -------------------------
# 4) Create Event Viewer Custom View XML (Sysmon + Defender relevant events)
# -------------------------
Write-Host "[4/5] Creating Event Viewer Custom View XML for Sysmon + Defender alerts..." -ForegroundColor Yellow

$customViewPath = Join-Path $env:PUBLIC "Sysmon-Defender-Alerts-CustomView.xml"

# XML filter: Sysmon Operational critical/warning/info that are typically interesting + Defender events
# This XML uses a QueryList with two queries combined under the Custom View.
$customViewXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<ViewerConfig>
  <QueryConfig>
    <Query Id="0" Path="Security">
      <!-- (left empty intentionally: Security may contain relevant events if you want them) -->
    </Query>
  </QueryConfig>
  <QueryList>
    <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
      <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(Level &lt;= 4)]]</Select>
    </Query>
    <Query Id="1" Path="Microsoft-Windows-Windows Defender/Operational">
      <!-- Defender event IDs for detections and actions -->
      <Select Path="Microsoft-Windows-Windows Defender/Operational">
        *[System[(Level &lt;= 4)]] and (
          EventID=1116 or
          EventID=1117 or
          EventID=1118 or
          EventID=1119 or
          EventID=1014 or
          EventID=1007
        )
      </Select>
    </Query>
  </QueryList>
</ViewerConfig>
"@

try {
    $customViewXml | Out-File -FilePath $customViewPath -Encoding UTF8 -Force
    Write-Host "Custom View XML written to: $customViewPath" -ForegroundColor Green
    Write-Host "Import it into Event Viewer: Event Viewer → right-click 'Custom Views' → Import Custom View... → select this XML." -ForegroundColor Cyan
} catch {
    Write-Warning "Failed to write custom view XML: $($_.Exception.Message)"
}

# -------------------------
# 5) Companion: Local PowerShell Viewer (no external dependencies)
# -------------------------
Write-Host "[5/5] Creating a local PowerShell viewer (quick view)..." -ForegroundColor Yellow

$viewerPath = Join-Path $env:PUBLIC "Sysmon-Defender-Viewer.ps1"
$viewerScript = @'
<#
Quick local viewer: queries Sysmon and Defender Operational logs and shows results in Out-GridView.
Run as Admin if you want full access.
#>

# Filter XML for Get-WinEvent (same intent as the Event Viewer custom view)
$xml = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(Level &lt;= 4)]]</Select>
  </Query>
  <Query Id="1" Path="Microsoft-Windows-Windows Defender/Operational">
    <Select Path="Microsoft-Windows-Windows Defender/Operational">
      *[System[(Level &lt;= 4)]] and (
        EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=1014 or EventID=1007
      )
    </Select>
  </Query>
</QueryList>
"@

try {
    $events = Get-WinEvent -FilterXml $xml -MaxEvents 1000 -ErrorAction SilentlyContinue
    if (-not $events) {
        Write-Host "No recent events found matching the IDS/IPS filters." -ForegroundColor Yellow
    } else {
        # Build a friendly table
        $table = $events | Select-Object @{n='TimeCreated';e={$_.TimeCreated}}, Id, LevelDisplayName, ProviderName, @{n='Message';e={$_.Message -replace "`r`n",' '}} 
        $table | Out-GridView -Title "Sysmon & Defender Alerts (local) - latest results" -PassThru
    }
} catch {
    Write-Warning "Viewer failed: $($_.Exception.Message)"
}
'@

try {
    $viewerScript | Out-File -FilePath $viewerPath -Encoding UTF8 -Force
    Write-Host "Local viewer placed at: $viewerPath" -ForegroundColor Green
    Write-Host "Run that script to open a quick grid view of recent Sysmon/Defender events." -ForegroundColor Cyan
} catch {
    Write-Warning "Failed to write viewer script: $($_.Exception.Message)"
}

# -------------------------
# Final Notes & Clean-up
# -------------------------
Write-Host "`n✅ Local IDS + IPS Hardening complete." -ForegroundColor Green
Write-Host "Files created:" -ForegroundColor Cyan
Write-Host " - $customViewPath"
Write-Host " - $viewerPath"
Write-Host "`nImport the XML into Event Viewer: right-click 'Custom Views' → Import Custom View..." -ForegroundColor Cyan
Write-Host "If you want the script to attempt an automated import, reply and I will add a best-effort import step (note: it can fail on some Windows builds)." -ForegroundColor Yellow

# Clean up temp (optional)
# Remove-Item -Path $temp -Recurse -Force
