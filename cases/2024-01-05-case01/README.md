# 📁 KC7 Case 01: A Scandal in Valdoria (Editorial Intern Phishing Campaign)

## Summary
A targeted phishing campaign compromised two editorial interns, resulting in unauthorized publication of a falsified article and confirmed data exfiltration.

## Status
Closed

## Owner / Analyst
krista.polly@microsoft.com

---

## Timeline

- **2024-01-05 09:42:05** — Sonia Gose receives phishing email from `newspaper_jobs@gmail.com`
- **2024-01-05 10:23:17** — Sonia clicks link; download of `Valdorian_Times_Editorial_Offer_Letter.docx` initiated
- **2024-01-05 10:24:04** — Malicious file written to `UL0M-MACHINE`
- **2024-01-05 10:24:32** — Payload activated; `hacktivist_manifesto.ps1` launched via WINWORD.EXE
- **2024-01-05 11:22:44** — Scheduled task created for hourly execution
- **2024-01-05 11:55:22** — SSH credentials discovered in script
- **2024-01-06 02:39:35** — C2 connection established via `plink.exe` to `136.130.190.181`
- **2024-01-10 08:48:16** — Ronnie McLovin receives phishing email from `valdorias_best_recruiter@gmail.com`
- **2024-01-10 08:55:07** — Ronnie clicks link; downloads `Editorial_J0b_Openings_2024.docx`
- **2024-01-10 08:55:17** — File written to `A37A-DESKTOP`
- **2024-01-10 08:55:50** — Payload activated; same script chain observed
- **2024-01-11 03:08:12** — Second C2 connection established via `plink.exe`
- **2024-01-31 09:47:51** — `fakestory.docx` downloaded from `hire-recruit.org`
- **2024-01-31 10:26:20** — File renamed to `OpEdFinal_to_print.docx`
- **2024-01-31 11:11:12** — Email sent from Ronnie to Clark Kent with falsified article
- **2024-01-31 11:44:58** — `.7z` archive created; dark web alert triggered
- **2024-02-01 02:15:01** — Files exfiltrated to `https://hirejob.com/exfil_processor/upload.php`

---

## Evidence & Queries

- **Suspicious emails:** E-002, E-006  
- **Malicious documents:** E-003, E-007  
- **Scheduled task creation:** E-004  
- **C2 connections:** E-005, E-007  
- **File manipulation and renaming:** E-008  
- **Exfiltration activity:** E-009, E-010  

**Sample KQL Queries:**
```kql
Email
| where sender == "newspaper_jobs@gmail.com" or sender == "valdorias_best_recruiter@gmail.com"

ProcessEvents
| where process_commandline contains "hacktivist_manifesto.ps1" or "plink.exe"

OutboundNetworkEvents
| where url contains "promotionrecruit.com" or "hirejob.com"
```
## Hypotheses

1. The phishing email to Sonia was part of a generic spam campaign = ❌  
2. The `.docx` file was benign and used only for social engineering = ❌  
3. Attackers maintained access via scheduled tasks = ✅  
4. Data exfiltration occurred via standard web protocols = ✅  
5. The attacker reused infrastructure across multiple cases = 🔄 Inconclusive

---

## Analysis

- Email headers failed SPF/DKIM validation, supporting phishing origin  
- Malicious `.docx` files triggered embedded PowerShell scripts (`hacktivist_manifesto.ps1`)  
- Scheduled tasks created silently on both UL0M-MACHINE and A37A-DESKTOP  
- SSH tunneling via `plink.exe` enabled remote access to attacker-controlled infrastructure  
- Attackers downloaded and renamed `fakestory.docx` to impersonate a legitimate OpEd  
- Email sent from Ronnie’s account to Clark Kent resulted in unauthorized publication  
- `.7z` archive creation and upload to `hirejob.com` confirmed data exfiltration  
- IOC overlap suggests broader campaign reuse, pending cross-case correlation

---

## Conclusion & Action Taken

- Compromised endpoints isolated and reimaged  
- Credentials rotated for affected users; MFA enforced  
- Malicious domains blocked at proxy and DNS  
- Editorial workflow updated to require multi-person approval  
- Legal and PR teams engaged for reputational mitigation  
- Dark web monitoring alert escalated to threat intel team  
- Case closed

---

## References / IOC List

- **Domains:**  
  - `promotionrecruit.com`  
  - `promotionrecruit.org`  
  - `hire-recruit.org`  
  - `hirejob.com`

- **IP Addresses:**  
  - `136.130.190.181`

- **Files:**  
  - `Valdorian_Times_Editorial_Offer_Letter.docx`  
  - `Editorial_J0b_Openings_2024.docx`  
  - `fakestory.docx`  
  - `OpEdFinal_to_print.docx`  
  - `hacktivist_manifesto.ps1`  
  - `.7z` archive

- **Emails:**  
  - `newspaper_jobs@gmail.com`  
  - `valdorias_best_recruiter@gmail.com`

---

## Lessons Learned / Next Steps

- Editorial systems must enforce multi-person approval for sensitive publications  
- Phishing awareness training should include realistic job-themed lures  
- Scheduled task creation should be monitored and alerted in real time  
- SSH tunneling tools like `plink.exe` should be flagged in non-admin environments  
- Develop playbook for editorial compromise scenarios  
- Cross-case IOC enrichment needed to confirm infrastructure reuse  
- Automate detection of `.docx` files spawning PowerShell or network activity