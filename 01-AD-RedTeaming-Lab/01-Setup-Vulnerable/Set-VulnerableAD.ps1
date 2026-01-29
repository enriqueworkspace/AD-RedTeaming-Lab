# Set-VulnerableAD.ps1
# CAUTION: Execute ONLY in a controlled laboratory environment.
Import-Module ActiveDirectory

Write-Host "[+] Initializing Vulnerable AD Configuration..." -ForegroundColor Cyan
$pass = ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force

# --- 1. AS-REP Roasting Setup (Universal Compatibility) ---
Write-Host "[*] Configuring AS-REP Roasting vulnerability..." -ForegroundColor White
$asrepUser = "victim.asrep"

if (-not (Get-ADUser -Filter "SamAccountName -eq '$asrepUser'")) {
    New-ADUser -Name "Victim ASREP" -SamAccountName $asrepUser -AccountPassword $pass -Enabled $true
}
$currentUAC = (Get-ADUser -Identity $asrepUser -Properties userAccountControl).userAccountControl
Set-ADUser -Identity $asrepUser -Replace @{userAccountControl = $currentUAC -bor 0x400000}
Write-Host "[!] SUCCESS: AS-REP Roasting flag verified for '$asrepUser'." -ForegroundColor Green

# --- 2. Kerberoasting Setup ---
Write-Host "[*] Configuring Kerberoasting vulnerability..." -ForegroundColor White
$svcUser = "svc_sql"
if (-not (Get-ADUser -Filter "SamAccountName -eq '$svcUser'")) {
    New-ADUser -Name "SQL Service Account" -SamAccountName $svcUser -AccountPassword $pass -Enabled $true
}
setspn -S "MSSQLSvc/sql01.company.local:1433" $svcUser
Write-Host "[!] SUCCESS: User '$svcUser' is now vulnerable to Kerberoasting (SPN assigned)." -ForegroundColor Yellow

Write-Host "`n[+] Setup complete. The Active Directory forest is now prepared for testing." -ForegroundColor Green