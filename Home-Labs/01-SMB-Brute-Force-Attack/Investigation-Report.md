# Investigation Report — SMB Brute-Force and Finance Share Access

## Executive summary

On 20 October 2026, I ran a controlled home-lab simulation from Kali Linux (`192.168.29.163`) against a Windows 10 endpoint (`192.168.29.72`). The simulation generated repeated failed SMB authentication attempts. Wazuh raised a multiple-logon-failures alert. The same source IP and lab account were then seen in a successful network logon event, followed by a Windows event recording access to the Finance SMB share.

The evidence supports a sequence of failed authentication, successful network authentication, and share access during the lab run. The successful-logon rule mentions possible Pass-the-Hash activity, but the available event does not confirm that technique. Event ID 5140 records share access, not a file-specific download. The Kali `smbclient` output separately shows that I retrieved `Financial_Report.txt`. I did not open or review the file contents during this investigation.

## Scope and environment

| Item | Value |
|---|---|
| SIEM | Wazuh 4.14.7 |
| Monitored agent | `Windows10-Lab-01`, agent ID `001` |
| Windows computer | `WIN10-SOC-LAB` |
| Target IP | `192.168.29.72` |
| Source IP | `192.168.29.163` (Kali Linux) |
| Account | `SOC-LabUser` |
| Service | SMB over TCP/445 |
| SMB share | `Finance` |
| Windows directory behind the share | `C:\Finance` |
| Test file retrieved | `Financial_Report.txt` |

## Timeline

The raw Windows `systemTime` fields are recorded in UTC. The Wazuh dashboard timestamps below are the displayed local times (UTC+05:30). These can differ because the dashboard timestamp and the original Windows event time are not necessarily the same timestamp. The Windows event time is used to describe the event sequence.

| Windows event time (UTC) | Wazuh dashboard timestamp (local) | Evidence | Interpretation |
|---|---|---|---|
| 2026-10-20 14:08:04.762Z | 19:38:06.156 | Event ID 4625; Wazuh Rule 60204, level 10 | Multiple Windows logon failures. The captured failure has substatus `0xC000006A`, indicating an incorrect password. |
| 2026-10-20 14:08:05.153Z | 19:38:06.218 | Event ID 4624; Wazuh Rule 92652, level 6 | Successful network logon for `SOC-LabUser` from `192.168.29.163`; logon type 3 and NTLM V2. |
| 2026-10-20 14:09:36.133Z | 19:39:37.659 | Event ID 5140; Wazuh Rule 67017, level 3 | Network share access. The record identifies the Finance SMB share, account `SOC-LabUser`, and source `192.168.29.163`. |

Based on the raw Windows event times, the successful logon occurred about 0.391 seconds after the failed-logon event shown above. The share-access event occurred about 90.980 seconds after the successful logon. The matching account and source IP support correlation, while the Kali terminal output provides separate evidence for the file retrieval.

## Detection 1 — Multiple Windows logon failures

- **Windows event:** Event ID 4625
- **Wazuh rule:** 60204 — `Multiple Windows Logon Failures`
- **Wazuh level:** 10
- **MITRE ATT&CK:** T1110 — Brute Force
- **Source IP:** `192.168.29.163`
- **Target account:** `SOC-LabUser`
- **Target endpoint:** `WIN10-SOC-LAB` / `192.168.29.72`
- **Failure details:** status `0xC000006D`, substatus `0xC000006A` (incorrect password)

Wazuh grouped repeated Windows authentication failures into an alert. This is consistent with the controlled password-testing activity shown in my Kali terminal.

Evidence: [03 — SMB brute-force detection](Screenshots/03-smb-brute-force-detection.png)

## Detection 2 — Successful network logon

- **Windows event:** Event ID 4624
- **Wazuh rule:** 92652
- **Wazuh level:** 6
- **Account:** `SOC-LabUser`
- **Source IP:** `192.168.29.163`
- **Target endpoint:** `WIN10-SOC-LAB` / `192.168.29.72`
- **Logon type:** 3 (network)
- **Authentication package:** NTLM V2
- **Windows event time:** 20 Oct 2026, 14:08:05.153 UTC
- **Wazuh dashboard timestamp:** 20 Oct 2026, 19:38:06.218 (UTC+05:30)

The successful event followed the failed logon in the raw Windows event time. The matching account and source IP make this a useful correlation. Logon type 3 is a network logon and should not be described as an RDP logon.

The Wazuh rule description mentions possible Pass-the-Hash activity, but the available event fields do not prove Pass-the-Hash. I treated this as an alert suggestion, not a confirmed finding.

Evidence: [04 — SMB successful network logon](Screenshots/04-smb-successful-network-logon.png)

## Detection 3 — Finance SMB share access

- **Windows event:** Event ID 5140
- **Wazuh rule:** 67017 — `A network share was accessed.`
- **Wazuh level:** 3
- **SMB share:** `Finance` (`\\*\Finance`)
- **Local Windows directory behind the share:** `C:\Finance`
- **Account:** `SOC-LabUser`
- **Source IP:** `192.168.29.163`
- **Windows event time:** 20 Oct 2026, 14:09:36.133 UTC
- **Wazuh dashboard timestamp:** 20 Oct 2026, 19:39:37.659 (UTC+05:30)
- **MITRE mapping shown by Wazuh:** T1021.002

Event ID 5140 records access to a network share. It is not file-specific and does not prove that a particular file was read or downloaded. Wazuh maps this event to T1021.002 (SMB/Windows Admin Shares), but the event shown here identifies the `Finance` share; the mapping alone does not establish that an administrative share was accessed.

The Kali terminal output separately shows that I retrieved `Financial_Report.txt` from the Finance SMB share. I did not open or review its contents.

Evidence: [05 — SMB Finance share access](Screenshots/05-smb-finance-share-access.png)

## Key findings

1. Wazuh detected repeated failed Windows logons associated with the controlled SMB test.
2. A successful network logon for the same lab account and source IP followed.
3. Windows Event ID 5140 recorded subsequent access to the Finance SMB share.
4. The Kali `smbclient` output showed retrieval of `Financial_Report.txt`; the file contents were not reviewed.

## Investigation disposition

This was an authorized home-lab simulation, not a production incident. The observed activity was consistent with the actions I performed in the lab. No production containment or remediation was performed.

## Limitations

- The successful-logon alert mentions possible Pass-the-Hash activity, but the available evidence does not confirm it.
- Windows Event ID 5145 was not available in the collected telemetry, so I could not use it to examine detailed file-share access requests.
- Windows Event ID 5140 confirmed access to the Finance SMB share. The Kali terminal output separately confirmed the download of `Financial_Report.txt`. I did not review the file contents during this investigation.
- The report covers the events and evidence collected for this simulation; it does not claim that every possible post-authentication activity was investigated.

## Recommendations

1. Use threshold-based alerting for repeated failed logons, with tuning to reduce unnecessary alerts.
2. Correlate failed and successful network logons by account, source IP, endpoint, and time.
3. Enable and validate detailed file-share auditing where appropriate, including Event ID 5145, and confirm the events reach the SIEM.
4. Apply least privilege to SMB share and NTFS permissions; review who can read sensitive shares.
5. Monitor for unexpected SMB access, account changes, and suspicious follow-on process activity.
6. Do not expose passwords or other credentials in public screenshots or reports.

## Evidence screenshots

- [01 — SMB brute-force execution](Screenshots/01-smb-brute-force-execution.png)
- [02 — SMB file retrieval](Screenshots/02-smb-file-retrieval.jpeg)
- [03 — SMB brute-force detection](Screenshots/03-smb-brute-force-detection.png)
- [04 — SMB successful network logon](Screenshots/04-smb-successful-network-logon.png)
- [05 — SMB Finance share access](Screenshots/05-smb-finance-share-access.png)
