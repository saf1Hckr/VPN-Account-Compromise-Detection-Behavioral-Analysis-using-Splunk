# 🔐 VPN Account Compromise Detection & Behavioral Analysis (Splunk SIEM Project)

## 📖 Project Overview

This project demonstrates a real-world Security Operations Center (SOC) investigation using Splunk SIEM to detect and analyze a VPN brute force attack that resulted in account compromise.

The analysis includes:

- Identifying brute force attempts  
- Detecting successful authentication after multiple failures  
- Tracking post-compromise user behavior  
- Performing user activity baseline analysis  
- Calculating average VPN usage per employee  
- Comparing anomalous vs normal account activity  

This project simulates a real enterprise incident investigation.

---

## 🛠️ Technologies Used

- Splunk Enterprise  
- SPL (Search Processing Language)  
- AWS EC2 (Linux environment)  
- VPN log dataset  
- Security investigation methodology (SOC workflow)  

---

## 🎯 Objectives

- Detect brute-force login attacks  
- Identify successful compromise events  
- Analyze user login patterns  
- Perform behavioral anomaly detection  
- Create actionable SOC incident findings  

---

## 🔎 Investigation Summary

### 🚨 Suspicious User Identified: Simon

Findings:

- 274 consecutive failed VPN login attempts from Canada  
- Successful authentication after brute force attempts  
- Additional login attempts following compromise  
- Sustained VPN access for 3–4 days  
- Activity stopped abruptly afterward  
- Account behavior did not align with historical employee baseline  

### 📊 Indicators of Compromise

- High-volume authentication failures  
- Successful login immediately after brute force cycle  
- Login from foreign country  
- Behavioral deviation from average VPN usage  

**Severity Level:** 🔴 High  

**Likely Attack Type:**

- Brute Force Attack  
- Account Takeover (ATO)  
- Unauthorized VPN Access  

---

## 🔍 Step 2: Successful Authentication After Failures

After identifying the initial brute force noise, logs were analyzed for any successful authentication events.

### Observation for User "Simon":

- **1 Successful Authentication:** Status transitioned to `built` in VPN logs  
- **Post-Compromise Activity:** Additional login activity recorded for 3–4 consecutive days  
- **Cessation of Activity:** Logs stopped abruptly after the 4th day  

### Timeline Query:

```spl
index=vpn_logs UserName="Simon"
| stats count by action, Source_Country, Source_ip
```

<p align="center">
  <img src="screenshots/brute_force.png" width="800"/>
</p>

---

## 🧠 Step 3: Behavioral Pattern Analysis

The correlated data confirms a pattern highly consistent with:

- **Brute Force Attack:** High volume of failed attempts prior to success  
- **Account Takeover (ATO):** Unauthorized access followed by persistent use  
- **Unauthorized VPN Access:** Geographic deviation from employee’s home-base  

**Severity Level:** 🔴 High  

---

## 📊 Baseline Employee VPN Usage Analysis

To scientifically detect anomalies, average VPN usage per employee was calculated to establish a behavioral baseline.

### SPL Query – Calculate Average Daily VPN Usage

```spl
index=vpn_logs (action="built" OR action="teardown")
| sort 0 UserName _time
| streamstats current=f last(_time) as last_time last(action) as last_action by UserName
| eval duration=if(action="teardown" AND last_action="built", _time-last_time, null())
| where duration > 0
| eval day=strftime(last_time,"%Y-%m-%d")
| stats sum(duration) as total_seconds by UserName day
| eval total_hours=total_seconds/3600
| stats avg(total_hours) as avg_daily_hours by UserName
```

<p align="center">
  <img src="screenshots/brute_force.png" width="800"/>
</p>


<p align="center">
  <img src="screenshots/brute_force.png" width="800"/>
</p>


---

## 💡 Investigation Findings

- **Baseline Comparison:** Most employees showed consistent daily VPN usage hours.  
- The compromised account ("Simon") showed zero behavioral correlation with historical norms.  
- **Geographic Deviation:** Login source country differed from the employee's known base location.  
- **Primary Trigger:** Abnormal volume of failed authentications uncovered the breach.  

---

## 🕵️ Secondary User Investigation

A second user, Johnny Brown, was analyzed during the investigation sweep.

### Findings:

- Single successful login (`built`)  
- No failed attempts  
- No sustained or abnormal activity  
- No geographic anomaly detected  

<p align="center">
  <img src="screenshots/brute_force.png" width="800"/>
</p>


### Outcome:

Classified as **Low-Risk / Informational**.  
No further action required.

---

## 🛡️ Indicators of Compromise (IOCs)

- **Authentication Failures:** 274 failed attempts from a single source  
- **Geographic Anomaly:** Foreign login source for a domestic-based employee  
- **Success Pattern:** Successful authentication immediately after brute-force cycle  
- **Usage Anomaly:** Significant behavioral deviation from calculated baseline  

---

## 📉 Risk Assessment Matrix

| Indicator | Risk Level |
|------------|------------|
| 274 Failed Attempts | High |
| Successful Login After Failures | 🔴 Critical |
| Foreign Source Country | Medium-High |
| Continued Access for 3-4 Days | High |
| No MFA (If Disabled) | 🔴 Critical |

**Final Assessment:** ⚠️ Confirmed Account Compromise via Brute Force  

---

## 🚀 Recommended Mitigation Actions

### Immediate Remediation

- Force password reset  
- Invalidate all active VPN sessions for user "Simon"  

### Network Defense

- Block malicious IP addresses at the perimeter firewall  

### Identity Security

- Enforce Multi-Factor Authentication (MFA) across all VPN gateways  

### Forensic Audit

- Review post-authentication logs  
- Investigate lateral movement  
- Check for data exfiltration  

---

## 📊 Future Improvements

- **Automated Alerting:** Create Splunk alert for >10 failed attempts followed by success within 1 hour  
- **Geo-Fencing:** Implement GeoIP anomaly detection for unexpected countries  
- **Dashboards:** Build real-time UEBA dashboard for VPN monitoring  
- **Detection Engineering:** Correlate impossible travel scenarios  
- **Threat Simulation:** Simulate credential stuffing attack lab
  
