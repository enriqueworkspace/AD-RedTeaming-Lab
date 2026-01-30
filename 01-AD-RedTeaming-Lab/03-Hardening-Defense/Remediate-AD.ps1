<#
.SYNOPSIS
    Active Directory Hardening Script - Lab 01
.DESCRIPTION
    This script mitigates vulnerabilities exploited during Lab 01, including 
    AS-REP Roasting (Kerberos Pre-auth) and provides an audit for Kerberoasting 
    and GPO Delegation.
.NOTES
    Author: [Tu Nombre]
    Date: 2026
#>

# 1. Fix AS-REP Roasting (Enabling Kerberos Pre-auth)
Write-Host "[+] Enabling Kerberos Pre-auth for all vulnerable users..." -ForegroundColor Green

# We search for users with the 0x400000 bit (UF_DONT_REQUIRE_PREAUTH) set and remove it
$vulnerableUsers = Get-ADUser -Filter 'DoesNotRequireKerberosPreauth -eq $True'

if ($vulnerableUsers) {
    $vulnerableUsers | ForEach-Object {
        Set-ADUser -Identity $_ -Replace @{userAccountControl=($_.userAccountControl -band (-bnot 0x400000))}
        Write-Host "    [Fixed] Pre-auth enabled for: $($_.Name)" -ForegroundColor Gray
    }
} else {
    Write-Host "    [!] No vulnerable users found. Pre-auth is already enforced." -ForegroundColor Yellow
}

# 2. Audit Kerberoastable Accounts
Write-Host "`n[+] Identifying accounts with SPNs (Potential Kerberoasting targets)..." -ForegroundColor Yellow
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName

# 3. Secure GPO Delegations
Write-Host "`n[+] Manual Action Required: Review GPO delegations in GPMC.msc" -ForegroundColor Cyan
Write-Host "    Check 'Vulnerable_Policy' -> Delegation tab -> Remove non-admin write permissions."