# Screenshots

This directory contains the five annotated evidence images for the SMB brute-force and share-access lab.

| File | Evidence |
|---|---|
| [01-smb-brute-force-execution.png](01-smb-brute-force-execution.png) | Kali simulation, failed attempts, successful SMB authentication, and share enumeration |
| [02-smb-file-retrieval.jpeg](02-smb-file-retrieval.jpeg) | `smbclient` output showing retrieval of `Financial_Report.txt` |
| [03-smb-brute-force-detection.png](03-smb-brute-force-detection.png) | Windows Event ID 4625 and Wazuh Rule 60204 |
| [04-smb-successful-network-logon.png](04-smb-successful-network-logon.png) | Windows Event ID 4624 and Wazuh Rule 92652 |
| [05-smb-finance-share-access.png](05-smb-finance-share-access.png) | Windows Event ID 5140 and Wazuh Rule 67017 |

The screenshots support the evidence discussed in [Attack-Execution.md](../Attack-Execution.md) and [Investigation-Report.md](../Investigation-Report.md). Event ID 5140 proves network share access, not a file-specific download; the file retrieval is evidenced separately by the Kali terminal output.
