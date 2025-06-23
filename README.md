# Suspicious Login Activity Detection with Splunk

This project detects and visualizes SSH login activity from Linux `auth.log` using **Splunk Cloud**. It focuses on identifying **failed login attempts**, **successful logins**, and **potential brute force attacks**.

---

## Tech Stack

- **Splunk Cloud**
- **Linux auth.log data**
- **SPL (Search Processing Language)**

---

## What This Project Does

- Analyzes `auth.log` data using Splunk Cloud
- Extracts failed and successful login attempts
- Detects brute-force patterns (5+ fails within 5 minutes)
- Visualizes all insights in a dashboard

---

## How It Works

1. Uploaded `auth.log` file into Splunk Cloud
2. Set **sourcetype** to `linux_secure`
3. Used **SPL queries** to extract:
   - Failed logins
   - Source IP addresses
   - Successful logins by user
   - Brute-force patterns
4. Created a dashboard with 4 key panels

---

## Dashboard Screenshots

> *(Upload screenshots here once you take them from your Splunk dashboard)*

---

## Key SPL Queries

### 1. Failed Logins by IP

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "message repeated (?<repeat_count>\d+) times"
| eval repeat_count = if(isnull(repeat_count), 1, tonumber(repeat_count))
| rex field=_raw "from\s(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats sum(repeat_count) as total_failed_attempts by src_ip
| sort -total_failed_attempts

### **2. Successful Logins by User and IP**

index=main sourcetype=linux_secure "Accepted password"
| rex field=_raw "for\s(?<user>\w+)\sfrom\s(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by user, src_ip
| sort -count

### **3.Failed Logins Over Time**
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "message repeated (?<repeat_count>\d+) times"
| eval repeat_count = if(isnull(repeat_count), 1, tonumber(repeat_count))
| timechart span=1h sum(repeat_count) as failed_logins

### **4. Brute Force Detection (5+ in 5 min)**
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "message repeated (?<repeat_count>\d+) times"
| eval repeat_count = if(isnull(repeat_count), 1, tonumber(repeat_count))
| rex field=_raw "from\s(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=5m
| stats sum(repeat_count) as failed_attempts by src_ip, _time
| where failed_attempts > 5
| sort -_time
