# SMB Brute-Force Attack and Investigation

## Project overview

In this home lab, I simulated repeated SMB authentication failures against a Windows endpoint, followed by successful authentication and access to a test SMB share. I used Wazuh to review Windows Security events, correlate the observed activity, and investigate the sequence.

> **Lab scope:** This is a controlled, authorized lab using a Kali Linux source and a Windows 10 endpoint. The Finance share and its file contain fictional test data.

## Environment

- **SIEM:** Wazuh 4.14.7
- **Source system:** Kali Linux
- **Target endpoint:** Windows 10 (`WIN10-SOC-LAB`)
- **Wazuh agent name:** `Windows10-Lab-01`
- **Target IP:** `192.168.29.72`
- **Source IP:** `192.168.29.163`
- **Protocol/service:** SMB over TCP/445
- **Account used in the lab:** `SOC-LabUser`
- **SMB share:** `Finance` (mapped to the Windows directory `C:\Finance`)
- **Test file:** `Financial_Report.txt`

## Evidence and documents

- [Attack execution](Attack-Execution.md) — lab setup, commands, and simulation evidence.
- [Investigation report](Investigation-Report.md) — Wazuh alerts, event correlation, findings, and defensive recommendations.
- [Screenshots](Screenshots/) — five annotated images documenting execution, detection, successful authentication, share access, and file retrieval.

## Key evidence collected

| Evidence | Details |
|---|---|
| Windows failed logon | Event ID 4625; bad-password substatus `0xC000006A` |
| Wazuh failure detection | Rule 60204, “Multiple Windows Logon Failures,” level 10; MITRE ATT&CK T1110 |
| Windows successful logon | Event ID 4624; logon type 3 (network); NTLM V2 |
| Wazuh successful-logon alert | Rule 92652, level 6 |
| Windows share access | Event ID 5140; Finance SMB share; Wazuh rule 67017, level 3 |
| File retrieval | Kali `smbclient` output shows `Financial_Report.txt` being retrieved |

## Key Findings

I generated repeated failed network logons, followed by a successful network logon from the same source IP using the same lab account. A later Event ID 5140 recorded access to the Finance SMB share. The matching source IP and account support correlation of these events.

The Kali terminal output separately shows that I downloaded `Financial_Report.txt` from the Finance SMB share. I did not open or review the file contents as part of this investigation.

## Limitations

- The successful-logon alert mentions possible Pass-the-Hash activity, but the available evidence does not confirm it.
- Windows Event ID 5145 was not available in the collected logs, so I could not use it to examine detailed file-share access requests.
- Windows Event ID 5140 confirmed access to the Finance share. The Kali terminal output separately confirmed the download of `Financial_Report.txt`. I did not review the file contents during this investigation.

