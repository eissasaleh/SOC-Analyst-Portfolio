# Attack Execution — SMB Authentication Testing and Share Access

## Objective

The goal of this lab was to simulate an SMB brute-force attempt against a Windows endpoint, generate multiple failed login attempts followed by a successful login, enumerate the available SMB shares, and download a test file from the Finance shared folder (SMB share). The resulting Windows Security events were then investigated in Wazuh to understand how the failed logins, successful login, and share access appeared in the logs.

## Lab environment

| Component | Value |
|---|---|
| Source system | Kali Linux |
| Source IP | `192.168.29.163` |
| Target endpoint | Windows 10, `WIN10-SOC-LAB` |
| Target IP | `192.168.29.72` |
| Service | SMB over TCP/445 |
| Lab account | `SOC-LabUser` |
| Finance shared folder (SMB share) | `Finance`, mapped to `C:\Finance` |
| Test file | `Financial_Report.txt` |

## Execution sequence

**Figure 1 — SMB authentication testing and share enumeration**

![SMB brute-force execution and share enumeration](Screenshots/01-smb-brute-force-execution.png)

### 1. Confirm source and target networking

The Kali system's source IP was `192.168.29.163`. A TCP connectivity check confirmed that SMB port 445 was reachable on the Windows endpoint.

**Commands:**

```bash
ip -4 addr
nc -zv 192.168.29.72 445
```

- `ip -4 addr` displays IPv4 addresses configured on Kali.
- `nc -zv` checks whether the target's TCP port 445 is reachable.

### 2. Prepare a controlled test list

The test list contained ten invalid password entries followed by the valid lab credential. The list was saved to `/tmp/smb-password11`.

### 3. Test SMB authentication

CrackMapExec submitted the prepared list to the SMB service. The output showed ten `STATUS_LOGON_FAILURE` results followed by successful authentication.

**Command:**

```bash
crackmapexec smb 192.168.29.72 -u SOC-LabUser -p /tmp/smb-password11
```

The command tested the passwords in the list against the SMB target and identified the valid credential when authentication succeeded.

### 4. Enumerate shares and connect to Finance

The share enumeration output showed that the `Finance` SMB share was available with read access. The share maps to the Windows directory `C:\Finance`.

**Share enumeration command (password masked):**

```bash
crackmapexec smb 192.168.29.72 -u SOC-LabUser -p 'ei***' --shares
```

**Connect to the share:**

```bash
smbclient //192.168.29.72/Finance -U 'WIN10-SOC-LAB\SOC-LabUser'
```

The `smbclient` command prompts for the account password rather than putting it directly in the command line.

### 5. Retrieve the test file

**Figure 2 — Retrieval of Financial_Report.txt from the Finance SMB share**

![SMB file retrieval output](Screenshots/02-smb-file-retrieval.jpeg)

Inside the `smbclient` session, the share was listed and `Financial_Report.txt` was retrieved. The listing showed a file size of 140 bytes. The file was downloaded to Kali Linux; its contents were not opened or reviewed as part of this investigation.

**Commands inside the `smbclient` session:**

```text
ls
get Financial_Report.txt
quit
```

- `ls` lists the files available in the share.
- `get Financial_Report.txt` retrieves the file to the local Kali working directory.
- `quit` exits the SMB client.

## Notes

- The lab used a dedicated standard account and fictional test data.
- Kali terminal output documents the authentication result and file retrieval. Windows Security events provide separate evidence of logon and share-access activity; the two sources should be correlated by account, source IP, target, and time.
