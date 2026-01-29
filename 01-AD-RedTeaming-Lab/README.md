# Lab 01: Active Directory Attack and Defense

## Project Overview
This laboratory demonstrates the identification, exploitation, and remediation of common security misconfigurations within an Active Directory environment. The project covers the full lifecycle of an infrastructure pentest, from initial environment preparation to final hardening.

## Environment Topology
The environment consists of a Windows Server 2022 Domain Controller, a Windows 11 workstation, and a Kali Linux attack node. All testing is performed within an isolated virtual network under the company.local domain.

| Hostname | Role | Operating System | IP Address |
| :--- | :--- | :--- | :--- |
| DC01 | Domain Controller | Windows Server 2022 | 192.168.0.25 |
| DC02 | Workstation | Windows 11 | 192.168.0.30 |
| kali-attacker | Penetration Testing Host | Kali Linux | 192.168.0.205 |

## Phase 1: Vulnerability Setup

To simulate a realistic insecure enterprise environment, a custom PowerShell script was developed and executed on **DC01**. This phase involved technical challenges regarding Active Directory attribute manipulation and environment stabilization.

### 1.1 Automated Configuration
The setup script (`01-Setup-Vulnerable/Set-VulnerableAD.ps1`) automates the following misconfigurations:
* **AS-REP Roasting**: Creation of the `victim.asrep` account with Kerberos Pre-Authentication disabled.
* **Kerberoasting**: Creation of the `svc_sql` service account with a registered Service Principal Name (SPN).

### 1.2 Troubleshooting & Script Evolution
During execution, several limitations were identified regarding standard PowerShell parameters for specific AD attributes. The following table documents the technical hurdles and their respective resolutions:

| Issue | Root Cause | Resolution |
| :--- | :--- | :--- |
| `New-ADUser` error | Account already existed from previous execution attempts. | Implemented logic to verify object existence before initialization. |
| Parameter Binding Failure | Version-specific cmdlet limitations prevented the use of `-DoesNotRequireKerberosPreauth`. | Transitioned to a **Bitwise Operation** directly on the `userAccountControl` attribute. |
| Attribute Persistence | Flag modification failed when bundled with account creation. | Decoupled account creation from attribute modification using the `-Replace` operator. |

### 1.3 Technical Validation (Verification)
Manual and automated verifications were performed to confirm that the environment reached the required vulnerable state before proceeding to the exploitation phase.

#### A. AS-REP Roasting Validation
The `DONT_REQ_PREAUTH` flag (bitmask `0x400000`) was verified for the `victim.asrep` user:
```powershell
Get-ADUser -Identity "victim.asrep" -Properties userAccountControl | Select-Object Name, @{Name="ASREP_Vulnerable"; Expression={if($_.userAccountControl -band 0x400000){$true}else{$false}}}
Result: `ASREP_Vulnerable: True`

#### B. Kerberoasting Validation
The Service Principal Name (SPN) registration was confirmed for the service account:

```PowerShell
setspn -L svc_sql
Result: `MSSQLSvc/sql01.company.local:1433` successfully mapped to the `svc_sql` account.

## Phase 2: Exploitation
This phase documents the step-by-step process of exploiting the pre-configured vulnerabilities to escalate privileges within the domain.

### 2.1 Enumeration
Initial reconnaissance is performed from the kali-attacker node to identify active hosts and services.
(Pending documentation of Nmap/Netexec results)

### 2.2 Initial Access via AS-REP Roasting
(Pending documentation)

### 2.3 Privilege Escalation via Kerberoasting
(Pending documentation)

## Phase 3: Hardening and Remediation
This section will contain the security controls and PowerShell scripts required to remediate the identified vulnerabilities and monitor for similar attack patterns.