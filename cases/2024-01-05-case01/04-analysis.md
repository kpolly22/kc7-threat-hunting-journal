# Analysis — Case 01: A Scandal in Valdoria (Editorial Intern Phishing Campaign)

This analysis maps observed adversary behaviors to the MITRE ATT&CK® framework, providing tactical insight into how the attack unfolded across multiple stages.

---

## Initial Access

**Tactic:** Initial Access  
**Technique:** T1566.001 – Phishing: Spearphishing Attachment  
**Description:** Adversary delivered malicious documents via targeted emails to Sonia Gose and Ronnie McLovin.  
**Evidence:**  
- [E-002 – Suspicious email to Sonia Gose](evidence/E-002_Suspicious_email_to_Sonia_Gose.md)  
- [E-006 – Suspicious email to Ronnie](evidence/E-006_Suspicious_email.md)  
**Query Reference:**  
```kql
Email
| where sender == "newspaper_jobs@gmail.com" and recipient == "sonia_gose@valdoriantimes.news"
```

## Execution

**Tactic:** Execution  
**Technique:** T1204.002 – User Execution: Malicious File  
**Description:** Victims opened malicious `.docx` files that triggered embedded PowerShell scripts.  
**Evidence:**  
- [E-003 – hacktivist_manifesto.ps1](evidence/E-003_hacktivist_manifesto_ps1.md)  
- [E-008 – Suspicious file fakestory.docx](evidence/E-008_Suspicious_file_fakestory_docx.md)  
**Query Reference:**  
```kql
FileCreationEvents
| where filename == "Valdorian_Times_Editorial_Offer_Letter.docx"
```

## Persistence

**Tactic:** Persistence  
**Technique:** T1053.005 – Scheduled Task/Job: Scheduled Task  
**Description:** The adversary created a scheduled task to execute `hacktivist_manifesto.ps1` on a recurring basis using PowerShell with ExecutionPolicy Bypass. This ensured the script would run hourly, maintaining access and enabling further actions without user interaction.  
**Evidence:**  
- [E-004 – Scheduled task created](evidence/E-004_Scheduled_task_created.md)  
**Query Reference:**  
```kql
ProcessEvents
| where process_commandline contains "hacktivist_manifesto.ps1"
| where hostname == "UL0M-MACHINE"
```

## Credential Access

**Tactic:** Credential Access  
**Technique:** T1552.001 – Unsecured Credentials: Credentials in Files  
**Description:** The PowerShell script `hacktivist_manifesto.ps1` contained hardcoded SSH credentials used to establish remote access. These credentials were embedded directly in the command line, exposing sensitive authentication data without encryption or obfuscation.  
**Evidence:**  
- [E-003 – hacktivist_manifesto.ps1](evidence/E-003_hacktivist_manifesto_ps1.md)  
**Credentials Discovered:**  
- Username: `$had0w`  
- Password: `thruthW!llS3tUfree`  
**Query Reference:**  
```plaintext
powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\hacktivist_manifesto.ps1
```

## Command and Control

**Tactic:** Command and Control  
**Technique:** T1219 – Remote Access Tool  
**Description:** The adversary used `plink.exe` to establish remote access to compromised machines via SSH. This allowed them to maintain control over the environment and execute commands non-interactively. Connections were made to two separate C2 servers, indicating infrastructure reuse and campaign scaling.  
**Evidence:**  
- [E-005 – Adversary’s C2 server](evidence/E-005_Adversarys_C2_server.md)  
- [E-007 – Second C2 server](evidence/E-007_Adversarys_second_C2_server.md)  
**Query Reference:**  
```kql
ProcessEvents
| where process_commandline contains "plink.exe"
| where hostname in ("UL0M-MACHINE", "A37A-DESKTOP")
```
## Collection

**Tactic:** Collection  
**Technique:** T1560.001 – Archive Collected Data  
**Description:** The adversary used `.7z` to compress `.docx` files from Ronnie’s machine, preparing them for exfiltration. This technique is commonly used to bundle sensitive documents into a single archive, often with password protection or obfuscation to evade detection.  
**Evidence:**  
- [E-009 – Dark Web Monitoring Alert](evidence/E-009_Dark_Web_Monitoring_Alert.md)  
- [E-010 – Exfiltrated data from Ronnie’s machine](evidence/E-010_Exfiltrated_data_from_Ronnies_machine.md)  
**Query Reference:**  
```kql
ProcessEvents
| where hostname == "A37A-DESKTOP"
| where process_commandline contains ".7z"
```

## Exfiltration

**Tactic:** Exfiltration  
**Technique:** T1041 – Exfiltration Over C2 Channel  
**Description:** After archiving sensitive `.docx` files using `.7z`, the adversary exfiltrated the data to a custom upload portal hosted on `hirejob.com`. This transfer occurred over standard web protocols, blending into normal outbound traffic and bypassing basic detection mechanisms.  
**Evidence:**  
- [E-010 – Exfiltrated data from Ronnie’s machine](evidence/E-010_Exfiltrated_data_from_Ronnies_machine.md)  
**Query Reference:**  
```kql
ProcessEvents
| where hostname == "A37A-DESKTOP"
| where process_commandline contains "hirejob.com"
```

## Impact Summary

This campaign demonstrates a full adversary kill chain targeting editorial interns, with clear reuse of tooling (`hacktivist_manifesto.ps1`, `plink.exe`) and infrastructure (`promotionrecruit.com`, `hirejob.com`). The attacker leveraged phishing for initial access, scheduled tasks for persistence, embedded credentials for remote control, and custom portals for exfiltration.

**Key Observations:**
- Attack spanned multiple users and machines, indicating lateral movement and campaign scaling
- Payloads were disguised as job-related documents, exploiting trust and urgency
- Exfiltration was conducted via web-based C2 channels, blending into normal traffic
- MITRE tactics observed: Initial Access, Execution, Persistence, Credential Access, Command and Control, Collection, Exfiltration

**Operational Takeaways:**
- Reinforce phishing awareness and document hygiene for interns and new hires
- Monitor for scheduled task creation and PowerShell execution with bypass flags
- Flag outbound connections to known recruitment-themed domains
- Track `.7z` usage and document archiving on endpoints with sensitive roles

This case file can be reused as a training artifact for SOC analysts, incident responders, and technical program managers focused on identity-based threats and adversary emulation.
