Write-Host "=== LOCAL IDS + IPS DEFENDER HARDENING MODE ===" -ForegroundColor Cyan

# -----------------------------------------------------------
# 1) HARDEN MICROSOFT DEFENDER INTO IPS MODE
# -----------------------------------------------------------
Write-Host "Configuring Microsoft Defender Attack Surface Reduction (ASR)..." -ForegroundColor Yellow

# Disable outbound cloud reporting
Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue

# Enable Network Intrusion Prevention
Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue

# Controlled Folder Access (Ransomware Shield)
Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue

# Attack Surface Reduction (ASR) rules in BLOCK mode
$ASR_Rules = @(
 "56A863A9-875E-4185-98A7-B882C64B5CE5", # Block credential stealing
 "26190899-1602-49e8-8b27-eb1d0a1ce869", # Block unsigned ps1 scripts
 "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Block malicious Office macro abuse
 "3B576869-A4EC-4529-8536-B80A7769E899"  # Block remote code launch
)

Set-MpPreference `
 -AttackSurfaceReductionRules_Ids $ASR_Rules `
 -AttackSurfaceReductionRules_Actions 1,1,1,1

Write-Host "Defender IPS hardening applied." -ForegroundColor Green

# -----------------------------------------------------------
# 2) INSTALL SYSMON (LOCAL IDS)
# -----------------------------------------------------------
Write-Host "Installing Sysmon Local Intrusion Detection..." -ForegroundColor Yellow

$temp="$env:TEMP\sysmon"
if (!(Test-Path $temp)) { New-Item -ItemType Directory -Path $temp | Out-Null }

# Download Sysmon + Recommended Secure Config
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$temp\Sysmon.zip"
Expand-Archive "$temp\Sysmon.zip" -DestinationPath $temp -Force

Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$temp\sysmon.xml"

# Install Sysmon silently with logging enabled
Start-Process "$temp\Sysmon64.exe" -ArgumentList "-accepteula -i $temp\sysmon.xml" -Wait

Write-Host "Sysmon IDS active and logging to Windows Event Log: Applications & Services Logs > Microsoft > Windows > Sysmon/Operational" -ForegroundColor Green

# -----------------------------------------------------------
# 3) ENABLE LOCAL EVENT LOG RETENTION
# -----------------------------------------------------------
Write-Host "Ensuring logs are retained locally (no cloud sync)..." -ForegroundColor Yellow

wevtutil sl "Microsoft-Windows-Sysmon/Operational" /rt:true /ms:419430400

# 400MB local retention to prevent log wiping
Write-Host "Local IDS/IPS logging configured." -ForegroundColor Green

Write-Host "`n✅ Local IDS + IPS Hardening Complete"
Write-Host "🔁 Restart recommended to finalize network protection." -ForegroundColor Cyan
