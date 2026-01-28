# Set-VulnerableAD.ps1
# PRECAUCIÓN: Ejecutar solo en entornos de laboratorio.

Import-Module ActiveDirectory

Write-Host "[+] Configurando usuarios vulnerables..." -ForegroundColor Cyan

# 1. AS-REP Roasting
$pass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
New-ADUser -Name "Victim ASREP" -SamAccountName "victim.asrep" -AccountPassword $pass -Enabled $true
# Aquí está la vulnerabilidad: DONT_REQ_PREAUTH
Set-ADAccountControl -Identity "victim.asrep" -DoesNotRequireKerberosPreauth $true

Write-Host "[!] Usuario 'victim.asrep' configurado para AS-REP Roasting." -ForegroundColor Yellow

# 2. Kerberoasting
New-ADUser -Name "SQL Service Account" -SamAccountName "svc_sql" -AccountPassword $pass -Enabled $true
# Aquí está la vulnerabilidad: Asignar un Service Principal Name (SPN)
setspn -S MSSQLSvc/sql01.contoso.local:1433 svc_sql

Write-Host "[!] Usuario 'svc_sql' configurado para Kerberoasting (SPN asignado)." -ForegroundColor Yellow

Write-Host "[+] Setup completado. El AD ahora tiene debilidades comunes para practicar." -ForegroundColor Green