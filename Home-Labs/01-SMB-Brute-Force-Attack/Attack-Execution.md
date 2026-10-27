# Attack Execution — SMB Authentication Testing and Share Access

## Objective

Simulate repeated SMB authentication failures against a Windows lab endpoint, then authenticate with the dedicated lab account, enumerate the available shares, and retrieve a fictional test file. The purpose is to generate observable telemetry for the Wazuh investigation documented separately in [Investigation-Report.md](Investigation-Report.md).

## Authorization and scope

This activity was performed in a controlled home lab against the author's Windows endpoint. Do not run these commands against systems without explicit authorization.

## Lab environment

| Component | Value |
|---|---|
| Source | Kali Linux |
| Target | Windows 10 lab endpoint, `WIN10-SOC-LAB` |
| Target IP | `192.168.29.72` |
| Source IP | `192.168.29.163` |
| Service | SMB over TCP/445 |
| Lab account | `SOC-LabUser` |
| Share | `Finance` |
| Test file | `Financial_Report.txt` |
| SIEM | Wazuh 4.14.7; Windows agent name `Windows10-Lab-01` |

## Execution sequence

### 1. Confirm source and target networking

The Kali terminal showed source address `192.168.29.163`. A TCP connectivity check confirmed that `192.168.29.72:445` was reachable.

### 2. Prepare a controlled test list

A short test list contained ten invalid password attempts followed by the valid credential for the dedicated lab account. The credential itself is intentionally omitted from this public report.

### 3. Perform SMB authentication testing

The lab used CrackMapExec to submit the test list to the SMB service. The terminal output showed ten `STATUS_LOGON_FAILURE` results followed by a successful authentication result.

### 4. Enumerate shares and access Finance

Using the dedicated lab account, the share enumeration output showed the `Finance` share with read access. The lab then connected to `//192.168.29.72/Finance` using `smbclient`.

### 5. Retrieve the test file

The share listing showed `Financial_Report.txt` (140 bytes). The `smbclient get` output showed the file being retrieved. The file contained fictional test finance data.

## Evidence screenshots

The redacted, annotated screenshots are available in the `Screenshots/` directory:

1. [01 — SMB brute-force execution](Screenshots/01-smb-brute-force-execution.png)
2. [02 — SMB file retrieval](Screenshots/02-smb-file-retrieval.jpeg)

Before publishing or replacing evidence images, verify that no credential is readable.

## Operational notes

- The password used for the simulation is not included in this document.
- The lab used a purpose-built standard user account, not a real production account.
- The successful authentication and file retrieval are based on Kali terminal output. Windows/Wazuh telemetry is documented separately and should be correlated by timestamp, account, and source IP.
