# Firewall RDP Connection Attempts Detection (True Positive)

## Lab Overview

This lab demonstrates the detection and investigation of repeated Remote Desktop Protocol (RDP) connection attempts using Splunk Enterprise Security and FortiGate firewall logs.

The objective was to identify suspicious RDP activity targeting TCP port **3389**, validate a detection capable of identifying repeated connection attempts, and investigate the resulting alert using firewall telemetry.

The investigation was conducted using FortiGate traffic logs and focused on determining whether the observed network activity justified a **True Positive** classification.

---

# Environment

| Component | Value |
|----------|-------|
| SIEM | Splunk Enterprise Security |
| Data Source | FortiGate Firewall |
| Index | `main` |
| Sourcetype | `fortigate_traffic` |

---

# Investigation

## Initial RDP Traffic Investigation

The investigation began by reviewing all firewall traffic targeting TCP port **3389 (Remote Desktop Protocol)**.

The initial search confirmed repeated RDP traffic directed toward the monitored destination, indicating recurring connection attempts that warranted further analysis.

The firewall logs provided visibility into:

- Timestamp
- Source IP
- Destination IP
- Destination Port
- Firewall Action

![Initial RDP Traffic Investigation](Screenshots/01-initial-rdp-traffic-investigation.png)

---

## RDP Source IP Statistics

After confirming repeated RDP traffic, statistical analysis was performed to determine which source generated the highest number of connection attempts.

One source IP was responsible for the majority of observed RDP traffic, making it the primary focus of the investigation.

This statistical view helped distinguish the dominant activity from normal background traffic and demonstrated a clear concentration of repeated RDP attempts originating from a single source.

![RDP Source IP Statistics](Screenshots/02-rdp-source-ip-statistics.png)

---

# Detection

## Detection Scenario

To validate the detection, repeated Remote Desktop connection attempts were intentionally generated in the lab environment using the Windows Remote Desktop client (`mstsc`).

Each connection attempt produced firewall events targeting TCP port **3389**, allowing the correlation search to evaluate the repeated activity.

The objective was to verify that the detection correctly identified repeated RDP connection attempts and generated an alert for analyst investigation.

---

## Detection Logic

The correlation search monitors FortiGate firewall traffic targeting TCP port **3389**.

It groups events by source IP address and generates a notable event whenever repeated RDP connection attempts exceed the configured threshold.

---

## Correlation Rule Configuration

A correlation search was configured in Splunk Enterprise Security to detect repeated RDP connection attempts targeting TCP port **3389**.

When the defined threshold was exceeded, Splunk Enterprise Security automatically generated a notable event for investigation.

![Correlation Rule Configuration](Screenshots/03-rdp-correlation-rule-configuration.png)

---

## Generated Notable Event

After generating repeated RDP activity, the correlation search successfully triggered and created a notable event.

This confirmed that the detection logic functioned as expected and identified the generated RDP activity.

![Generated Notable Event](Screenshots/04-generated-rdp-notable-event.png)

---

# Alert Investigation

## Investigating the Alert

The notable event was investigated by filtering the firewall logs for the alerted source IP.

The investigation confirmed repeated RDP connection attempts targeting TCP port **3389** over a short period of time.

The observed activity matched the expected behavior defined by the detection logic and justified further investigation.

Because this investigation relies on FortiGate firewall traffic logs, the available evidence confirms repeated RDP network activity. The firewall logs do not provide visibility into Windows authentication events or indicate whether authentication ultimately succeeded or failed.

![Alert Investigation](Screenshots/05-rdp-alert-investigation.png)

---

## Investigation Statistics

A final statistical review was performed to validate the investigation findings.

The results confirmed that the alerted source generated repeated RDP traffic exceeding the configured threshold.

This consistency across the investigation strengthened confidence that the detection accurately identified the intended network behavior.

![Investigation Statistics](Screenshots/06-rdp-investigation-statistics.png)

---

# Evidence Summary

The investigation identified the following indicators:

- Multiple repeated connections targeting TCP port **3389**.
- One dominant source IP responsible for the majority of observed activity.
- Correlation search threshold exceeded.
- Successful generation of a Splunk Enterprise Security notable event.
- Consistent firewall evidence throughout the investigation.

---

# MITRE ATT&CK

| Tactic | Technique |
|---------|-----------|
| Lateral Movement | [T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/) |

---

# Final Analysis

The investigation confirmed that the detection successfully identified repeated RDP connection attempts captured by the FortiGate firewall.

The observed traffic pattern was consistent with suspicious Remote Desktop activity originating from a single source IP and exceeded the configured detection threshold.

Based on the available firewall evidence, the detection correctly identified suspicious network behavior requiring analyst investigation.

---

# Conclusion

This lab demonstrates the complete workflow of developing, validating, and investigating an RDP detection using Splunk Enterprise Security.

The investigation confirmed that the correlation search accurately detected repeated RDP connection attempts, generated a notable event, and supported an evidence-based investigation using FortiGate firewall logs.

Based on the available evidence, the detection was classified as a **True Positive** because it successfully identified the intended suspicious network activity.
