# SMB Brute-Force Attack and Investigation

## Project overview

This home lab simulates repeated SMB authentication failures against a Windows endpoint, followed by successful authentication and access to a test SMB share. Wazuh is used to review Windows Security events and investigate the sequence.

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
| Windows share access | Event ID 5140; Finance share; Wazuh rule 67017, level 3 |
| File retrieval | Kali `smbclient` output shows `Financial_Report.txt` being retrieved |

## Findings at a glance

The lab generated repeated failed network logons, followed by a successful network logon from the same source IP using the same lab account. A subsequent Event ID 5140 records access to the Finance share. These events support correlation of the authentication and share-access activity. Event ID 5140 alone does **not** prove that a particular file was downloaded; the terminal output provides separate evidence of the file retrieval.

## Limitations

- Wazuh's successful-logon rule description mentions possible pass-the-hash activity, but the observed Event ID 4624 does not independently prove pass-the-hash.
- Detailed file-level auditing (Event ID 5145) was not available in this run.
- Share access and file retrieval are supported by different evidence sources and should not be presented as the same event.

## Evidence handling

The screenshots are uploaded in the `Screenshots/` directory. Public copies should not expose credentials; the complete credential must be unreadable while relevant event fields remain legible.
