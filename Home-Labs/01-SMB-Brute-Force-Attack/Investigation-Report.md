# Investigation Report — SMB Brute-Force and Finance Share Access

## Executive summary

In a controlled home-lab simulation on 20 October 2026, Kali Linux (`192.168.29.163`) generated repeated failed SMB authentication attempts against a Windows 10 endpoint (`192.168.29.72`). Wazuh raised a multiple-logon-failures alert. The same source IP and lab account were subsequently observed in a successful network logon event, followed by a Windows network-share access event for the Finance share.

The evidence supports a sequence of failed authentication, successful network authentication, and share access during the lab run. The successful-logon rule's text mentions possible pass-the-hash activity, but the available event does not independently establish that technique. Event ID 5140 confirms network-share access, not a file-specific download; the separate Kali `smbclient` output records the test-file retrieval.

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
| Share | `Finance` |
| Test file | `Financial_Report.txt` |

## Timeline

The Wazuh dashboard displays timestamps in the local dashboard time zone, while the raw Windows `systemTime` fields are in UTC. The table below uses the displayed Wazuh timestamps from the captured events.

| Dashboard timestamp (20 Oct 2026) | Evidence | Interpretation |
|---|---|---|
| 19:38:06.156 | Windows Event ID 4625; Wazuh Rule 60204, level 10 | Multiple Windows logon failures detected. A captured failure has substatus `0xC000006A`, indicating an incorrect password. |
| 19:38:06.218 | Windows Event ID 4624; Wazuh Rule 92652, level 6 | Successful network logon for `SOC-LabUser` from `192.168.29.163`; logon type 3 and NTLM V2. |
| 19:39:37.659 | Windows Event ID 5140; Wazuh Rule 67017, level 3 | A network share was accessed. The record identifies the Finance share, account `SOC-LabUser`, and source `192.168.29.163`. |

The sequence and matching account/source IP support correlation. They do not by themselves prove that every event was caused by the same exact tool action; the controlled lab execution and terminal evidence provide additional context.

## Detection 1 — Multiple Windows logon failures

- **Windows event:** Event ID 4625
- **Wazuh rule:** 60204 — `Multiple Windows Logon Failures`
- **Wazuh level:** 10
- **MITRE ATT&CK:** T1110 — Brute Force
- **Source IP:** `192.168.29.163`
- **Target account:** `SOC-LabUser`
- **Target endpoint:** `WIN10-SOC-LAB` / `192.168.29.72`
- **Failure details:** status `0xC000006D`, substatus `0xC000006A` (incorrect password)

The Wazuh rule aggregated repeated Windows authentication failures. This is consistent with the controlled password-testing activity shown in the Kali terminal.

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
- **Dashboard timestamp:** 20 Oct 2026, 19:38:06.218

The successful event followed the failed-logon alert by approximately 62 milliseconds in dashboard time. The matching account and source IP make this a meaningful correlation to investigate. Logon type 3 is a network logon; it should not be described as an RDP logon.

The Wazuh rule description mentions possible pass-the-hash activity, but the event fields shown here do not prove pass-the-hash. Treat that text as a heuristic alert description, not a confirmed finding.

Evidence: [04 — SMB successful network logon](Screenshots/04-smb-successful-network-logon.png)

## Detection 3 — Finance network-share access

- **Windows event:** Event ID 5140
- **Wazuh rule:** 67017 — `A network share was accessed.`
- **Wazuh level:** 3
- **Share:** `Finance` (`\\*\Finance`)
- **Local share path:** `C:\Finance`
- **Account:** `SOC-LabUser`
- **Source IP:** `192.168.29.163`
- **Dashboard timestamp:** 20 Oct 2026, 19:39:37.659
- **MITRE mapping shown by Wazuh:** T1021.002

Event ID 5140 records that a network share was accessed. The event is not file-specific and, on its own, does not prove a particular file was read or downloaded. The screenshot shows access to the Finance share; the separate Kali terminal evidence shows `Financial_Report.txt` being retrieved.

Evidence: [05 — SMB Finance share access](Screenshots/05-smb-finance-share-access.png)

## File-retrieval evidence

The Kali `smbclient` session listed `Financial_Report.txt` in the Finance share and displayed a successful `get Financial_Report.txt` result (file size 140 bytes). This is separate client-side evidence of the simulated retrieval.

Evidence: [02 — SMB file retrieval](Screenshots/02-smb-file-retrieval.jpeg)

## Correlation assessment

**Assessment:** The observed activity is consistent with the intended controlled SMB brute-force and share-access simulation.

Supporting points:
1. Repeated failed logons targeted `SOC-LabUser` on `WIN10-SOC-LAB` from the Kali IP.
2. A successful type-3 network logon for the same account and source IP followed.
3. A subsequent Event ID 5140 identified the Finance share, the same account, and the same source IP.
4. The Kali terminal separately recorded successful retrieval of `Financial_Report.txt`.

This is a controlled lab, so the simulation context and client-side output are known. In a real investigation, the same sequence should initially be treated as a hypothesis and corroborated with additional endpoint, share, and user-activity telemetry.

## Limitations

- Windows Event ID 5145 detailed share-access auditing was not available in the captured telemetry.
- Event ID 5140 establishes share access, not file-level retrieval.
- The rule description mentioning pass-the-hash is not proof of that technique.
- The report records only the events shown in the captured evidence; it does not claim that all possible post-authentication activity was investigated.

## Recommendations

1. Use threshold-based alerting for repeated failed logons, with suppression/tuning to reduce noise.
2. Correlate failed and successful network logons by account, source IP, endpoint, and time.
3. Enable and validate detailed file-share auditing where operationally appropriate, including Event ID 5145, and verify the events reach the SIEM.
4. Apply least privilege to share and NTFS permissions; review who can read sensitive shares.
5. Monitor for unexpected SMB access, account changes, and subsequent suspicious process activity.
6. Protect credentials and never publish passwords or credential lists in portfolio screenshots.

## Evidence screenshots

- [01 — SMB brute-force execution](Screenshots/01-smb-brute-force-execution.png)
- [02 — SMB file retrieval](Screenshots/02-smb-file-retrieval.jpeg)
- [03 — SMB brute-force detection](Screenshots/03-smb-brute-force-detection.png)
- [04 — SMB successful network logon](Screenshots/04-smb-successful-network-logon.png)
- [05 — SMB Finance share access](Screenshots/05-smb-finance-share-access.png)
