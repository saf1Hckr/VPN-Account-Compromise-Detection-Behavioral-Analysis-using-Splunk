# 🔐 VPN Account Compromise Detection & Behavioral Analysis using Splunk

## 📌 Project Overview

This project demonstrates a real-world Security Operations Center (SOC) investigation using Splunk SIEM to detect, analyze, and respond to a VPN brute force attack that led to a successful account compromise.

The project walks through the full incident lifecycle:
- Detecting high-volume failed login attempts
- Identifying successful authentication after brute force
- Performing timeline analysis
- Monitoring post-compromise activity
- Establishing baseline VPN usage per employee
- Detecting anomalous user behavior

This project simulates a real enterprise incident response investigation and highlights practical SOC analyst skills.

---

## 🎯 Project Goals

- Detect brute force attacks within VPN logs
- Identify potential account takeover events
- Analyze authentication timelines
- Compare compromised vs normal user behavior
- Perform behavioral baseline analysis
- Calculate average VPN usage per employee
- Document findings as a professional SOC case report

---

## 🛠️ Technologies Used

- Splunk Enterprise
- SPL (Search Processing Language)
- AWS EC2 (Linux environment)
- VPN authentication log dataset
- Cybersecurity investigation methodology (SOC workflow)

---

## 🔍 Dataset

The dataset consists of VPN authentication logs containing:

- UserName
- Action (failed, built, teardown)
- Source_Country
- Source IP
- EventTime

Actions observed:
- `failed` → Authentication failure
- `built` → Successful VPN session established
- `teardown` → VPN session terminated

---

# 🚨 Incident Investigation Case Study

## 🧑 Suspicious User: Simon

### Step 1: Detection of Brute Force Activity

Initial investigation revealed:

- 274 consecutive failed login attempts
- All originating from Canada
- Rapid authentication attempts within minutes

SPL Query Used:

```spl
index=vpn_logs UserName="Simon"
| stats count by action, Source_Country
```
