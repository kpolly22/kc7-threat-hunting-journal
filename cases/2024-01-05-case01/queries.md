# Detection Queries — Case 01 - A Scandal in Valdoria

This file documents the KQL queries used to investigate a phishing campaign targeting editorial interns. Queries are grouped by entity type and investigative purpose, with annotations for clarity and reuse.

---

## Employee Enumeration & Target Identification

```kql
Employees
| take 10 
```
* ### Purpose: Preview employee dataset for structure and sample entries

```kql
Employees
| count
```
* ### Purpose: Determine total number of employee records

```kql
Employees
| where name == "Clark Kent"
```
* ### Purpose: Identify targeted individual

```kql
Employees
| where role == "Editorial Intern"
```
* ### Purpose: Filter for potential phishing targets

```kql
Employees
| where name == "Sonia Gose"
```
* ### Purpose: Investigate secondary target or related individual

## 📧 Email Investigation

```kql
Email
| where recipient contains "clark_kent@valdoriantimes.news"
```
* ### Purpose: Trace inbound phishing attempts to Clark Kent

```kql
Email
| where sender contains "newspaper_jobs@gmail.com"
```
- ### Purpose: Flag suspicious sender linked to job scam

```kql
Email
| where sender contains "valdorias_best_recruiter@gmail.com"
```
* ### Purpose: Identify alternate phishing sender used in campaign

## 🌐 Network Activity

```kql
OutboundNetworkEvents
| where src_ip has "10.10.0.3"
```
* ### Purpose: Trace outbound traffic from Clark Kent’s machine

```kql
OutboundNetworkEvents
| where src_ip contains "10.10.0.19"
```
* ### Purpose: Investigate suspicious outbound traffic from A37A-DESKTOP

```kql
InboundNetworkEvents
| where src_ip contains "10.10.0.19"
```
* ### Purpose: Identify inbound connections to A37A-DESKTOP

```kql
Email
| where sender contains "valdorias_best_recruiter@gmail.com"
```
* ### Purpose: Identify alternate phishing sender used in campaign

```kql
OutboundNetworkEvents
| where src_ip contains "10.10.0.19"
| where url contains "fakestory"
```
* ### Purpose: Confirm exfiltration attempt via malicious URL

## 🗃️ File Creation Events

```kql
FileCreationEvents
| where hostname contains "UL0M-MACHINE"
```
* ### Purpose: Investigate file creation on suspected compromised host

```kql
FileCreationEvents
| where hostname contains "A37A-DESKTOP"
```
* ### Purpose: Trace file activity on target machine

```kql
FileCreationEvents
| where filename contains "Editorial_j0b_Openings_2024.docx"
```

* ### Purpose: Flag suspicious document used in phishing lure

```kql
FileCreationEvents
| where filename contains "fakestory.docx"
```

* ### Purpose: Identify payload or decoy file created during attack

## Process Execution Analysis

```kql
ProcessEvents
| where process_commandline contains "plink.exe"
```

* ### Purpose: Detect use of tunneling or remote access tools

```kql
ProcessEvents
| where hostname contains "UL0M-MACHINE"
| distinct process_commandline
```

* ### Purpose: Enumerate unique commands executed on UL0M-MACHINE

```kql
ProcessEvents
| where hostname contains "A37A-DESKTOP"
| distinct process_commandline
```

* ### Purpose: Identify unique processes on target machine

```kql
ProcessEvents
| where hostname contains "A37A-DESKTOP"
| where process_commandline contains "fakestory"
```

* ### Purpose: Confirm execution of suspicious document or payload

```kql
ProcessEvents
| where timestamp between (datetime(2024-01-21 07:00:00) .. datetime(2024-01-21 12:00:00))
| where hostname == "A37A-DESKTOP"
| order by timestamp asc
```

* ### Purpose: Build timeline of process activity during suspected compromise window

```kql
ProcessEvents
| where process_commandline contains ".7z"
```

* ### Purpose: Detect use of compression tools for staging or exfiltration

```kql
ProcessEvents
| where process_commandline contains "hirejob.com"
```
* ### Purpose: Identify command-line references to phishing domain

## Notes

- **All queries executed in KC7 lab environment.**
- **Results exported to timeline.md and analysis.md.**
- **MITRE ATT&CK tactics mapped in analysis.md.**
- **Queries reused in playbook for future editorial phishing scenarios.**
