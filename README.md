
## 📌 Overview

This project simulates an insider threat using PowerShell to perform data exfiltration and demonstrates detection using SIEM.

## 🎯 Objectives

* Simulate insider attack
* Detect malicious PowerShell execution
* Map activity to MITRE ATT&CK
* Generate SIEM alerts
* Perform SOC investigation

---

## 🧪 Lab Environment

Attacker VM → Victim VM → Sysmon → ELK Stack → Kibana

### Components

* Windows Attacker VM
* Windows Victim VM
* Sysmon log collection
* ELK Stack SIEM
* Kibana dashboard
* Atomic Red Team

---

## 🧠 MITRE ATT&CK Mapping

* T1059.001 – PowerShell Execution
* T1041 – Data Exfiltration
* T1003 – Credential Access (optional)
* Defense Evasion techniques

---

## ⚔️ Attack Scenario

1. Insider executes PowerShell
2. Encoded command used
3. Data collected
4. Data exfiltrated via network
5. Logs generated

---

## 🔍 Detection Workflow

1. Attack executed
2. Sysmon logs process creation
3. Logs forwarded to ELK
4. Detection rule triggered
5. Alert generated
6. SOC investigation

---

## 🛠️ Tools Used

* Sysmon
* ELK Stack
* Kibana
* PowerShell
* Atomic Red Team
* MITRE ATT&CK

---

## 🚨 Detection Use Cases

* PowerShell execution detection
* Encoded command detection
* Suspicious parent process
* Data exfiltration detection
* Credential dumping detection

---

## 📊 Screenshots

(Add Kibana dashboard screenshots)

---

## 🎯 SOC Analyst Skills Demonstrated

* SIEM Monitoring
* Threat Detection
* MITRE ATT&CK Mapping
* Log Analysis
* Incident Investigation
* Detection Engineering
