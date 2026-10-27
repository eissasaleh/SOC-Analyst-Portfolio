# Attack Execution — SMB Authentication Testing and Share Access

## Objective

In this lab, I simulated repeated SMB authentication failures against a Windows endpoint, then authenticated with the dedicated lab account, enumerated the available shares, and retrieved a fictional test file. The purpose was to generate observable telemetry for the Wazuh investigation documented separately in [Investigation-Report.md](Investigation-Report.md).

## Authorization and scope

I performed this activity in a controlled home lab against my Windows endpoint. These steps should only be run against systems for which explicit authorization has been granted.

## Lab environment

| Component | Value |
|---|---|
| Source | Kali Linux |
| Target | Windows 10 lab endpoint, `WIN10-SOC-LAB` |
| Target IP | `192.168.29.72` |
| Source IP | `192.168.29.163` |
| Service | SMB over TCP/445 |
| Lab account | `SOC-LabUser` |
| SMB share | `Finance`, mapped to `C:\Finance` |
| Test file | `Financial_Report.txt` |
| SIEM | Wazuh 4.14.7; Windows agent name `Windows10-Lab-01` |

## Execution sequence

### 1. Confirm source and target networking

The Kali terminal showed the source address `192.168.29.163`. A TCP connectivity check confirmed that the Windows endpoint at `192.168.29.72:445` was reachable.

### 2. Prepare a controlled test list

I prepared a short test list containing ten invalid password attempts followed by the valid credential for the dedicated lab account. The credential itself is intentionally omitted from this public report.

### 3. Perform SMB authentication testing

I used CrackMapExec to submit the test list to the SMB service. The terminal output showed ten `STATUS_LOGON_FAILURE` results followed by a successful authentication result.

### 4. Enumerate shares and access Finance

Using the dedicated lab account, I enumerated the available SMB shares and confirmed that the `Finance` share was listed with read access. I then connected to `//192.168.29.72/Finance` using `smbclient`.

The `Finance` SMB share maps to the Windows directory `C:\Finance`.

### 5. Retrieve the test file

The share listing showed `Financial_Report.txt` (140 bytes). The `smbclient get` output showed that I retrieved the file to Kali Linux. I did not open or review the file contents as part of this investigation.

## Evidence screenshots

The redacted, annotated screenshots are available in the [Screenshots](Screenshots/) directory:

1. [01 — SMB brute-force execution](Screenshots/01-smb-brute-force-execution.png)
2. [02 — SMB file retrieval](Screenshots/02-smb-file-retrieval.jpeg)

## Operational notes

- The password used for the simulation is not included in this document.
- I used a dedicated standard lab account, not a production account.
- Kali terminal output provides evidence of the authentication result and file retrieval. Windows/Wazuh telemetry provides separate endpoint-side evidence and should be correlated by timestamp, account, and source IP.
