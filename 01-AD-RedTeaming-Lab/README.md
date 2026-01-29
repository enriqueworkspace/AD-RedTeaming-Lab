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
To simulate a realistic insecure enterprise environment, a custom PowerShell script was developed and executed on DC01. This script automates the following misconfigurations:

1. **AS-REP Roasting:** Created a user account (victim.asrep) with Kerberos Pre-Authentication disabled.
2. **Kerberoasting:** Created a service account (svc_sql) with a registered Service Principal Name (SPN) and a weak password policy.
3. **GPO Abuse:** (Pending) Configuration of excessive write permissions on specific Group Policy Objects.

The setup script is located in the 01-Setup-Vulnerable directory.

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