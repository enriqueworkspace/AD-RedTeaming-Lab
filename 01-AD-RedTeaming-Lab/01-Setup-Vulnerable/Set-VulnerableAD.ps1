# Set-VulnerableAD.ps1
# CAUTION: Execute ONLY in a controlled laboratory environment.
# This script configures common Active Directory vulnerabilities for educational purposes.

Import-Module ActiveDirectory

Write-Host "[+] Initializing Vulnerable AD Configuration..." -ForegroundColor Cyan

# Define common password for lab accounts
$pass = ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force

# --- 1. AS-REP Roasting Setup ---
Write-Host "[*] Configuring AS-REP Roasting vulnerability..." -ForegroundColor White
try {
    $asrepUser = "victim.asrep"
    New-ADUser -Name "Victim ASREP" -SamAccountName $asrepUser -AccountPassword $pass -Enabled $true -ErrorAction Stop
    
    # Enable DONT_REQ_PREAUTH (The actual vulnerability)
    Set-ADAccountControl -Identity $asrepUser -DoesNotRequireKerberosPreauth $true
    Write-Host "[!] SUCCESS: User '$asrepUser' is now vulnerable to AS-REP Roasting." -ForegroundColor Yellow
} catch {
    Write-Host "[-] ERROR: Failed to create AS-REP user. It might already exist." -ForegroundColor Red
}

# --- 2. Kerberoasting Setup ---
Write-Host "[*] Configuring Kerberoasting vulnerability..." -ForegroundColor White
try {
    $svcUser = "svc_sql"
    New-ADUser -Name "SQL Service Account" -SamAccountName $svcUser -AccountPassword $pass -Enabled $true -ErrorAction Stop
    
    # Assign Service Principal Name (SPN) to the service account
    # Domain updated to: company.local
    setspn -S "MSSQLSvc/sql01.company.local:1433" $svcUser
    Write-Host "[!] SUCCESS: User '$svcUser' is now vulnerable to Kerberoasting (SPN assigned)." -ForegroundColor Yellow
} catch {
    Write-Host "[-] ERROR: Failed to create Service Account or assign SPN." -ForegroundColor Red
}

Write-Host "`n[+] Setup complete. The Active Directory forest is now prepared for testing." -ForegroundColor Green