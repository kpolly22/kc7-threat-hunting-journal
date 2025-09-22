# Hypotheses - Case 01: A Scandal in Valdoria (Editorial Intern Phishing Campaign)


This section outlines the initial and evolving hypotheses that guided the investigation. Each hypothesis is tracked with supporting or refuting evidence, pivot points, and operational impact.

---

## Hypothesis 1: The phishing email was a generic spam campaign

**Assumption:** The email received by Sonia Gose was part of a broad, non-targeted spam campaign.  
**Initial Indicators:**  
- Generic sender address (`newspaper_jobs@gmail.com`)  
- Subject line: “Editorial Internship Opportunity”  
**Pivot Point:**  
- Email to Ronnie McLovin contained identical language and attachment  
- Attachment triggered PowerShell script with embedded credentials  
**Conclusion:**  
- ❌ Refuted — campaign was targeted and weaponized  
**Operational Impact:**  
- Escalated to targeted phishing with embedded payloads

---

## Hypothesis 2: The `.docx` file was benign and used only for social engineering

**Assumption:** The attachment was used to lure victims into replying or clicking external links.  
**Initial Indicators:**  
- File named `Valdorian_Times_Editorial_Offer_Letter.docx`  
- No macros detected  
**Pivot Point:**  
- File creation triggered `hacktivist_manifesto.ps1` via scheduled task  
**Conclusion:**  
- ❌ Refuted — file was weaponized and used for execution  
**Operational Impact:**  
- Flagged `.docx` as delivery vector for embedded script

---

## Hypothesis 3: The attacker maintained access via scheduled tasks

**Assumption:** Persistence was achieved through scheduled execution of malicious scripts.  
**Initial Indicators:**  
- PowerShell command with ExecutionPolicy Bypass  
- Task scheduled to run hourly  
**Pivot Point:**  
- Task observed on both UL0M-MACHINE and A37A-DESKTOP  
**Conclusion:**  
- ✅ Confirmed  
**Operational Impact:**  
- Scheduled task creation added to detection logic

---

## Hypothesis 4: Data exfiltration occurred via standard web protocols

**Assumption:** The attacker used HTTP/S to exfiltrate data to a remote server.  
**Initial Indicators:**  
- Connection to `hirejob.com` observed in process command line  
- `.7z` archive created minutes before upload  
**Pivot Point:**  
- Upload path: `/exfil_processor/upload.php`  
**Conclusion:**  
- ✅ Confirmed  
**Operational Impact:**  
- Domain added to blocklist and retroactive traffic analysis initiated

---

## Hypothesis 5: The attacker reused infrastructure across multiple cases

**Assumption:** Domains and payloads used in this case were part of a broader campaign.  
**Initial Indicators:**  
- Similar domain structure (`promotionrecruit.com`, `hirejob.com`)  
- Reuse of `hacktivist_manifesto.ps1` across endpoints  
**Pivot Point:**  
- Matching IOC patterns in previous KC7 case  
**Conclusion:**  
- 🔄 Inconclusive — further correlation needed  
**Operational Impact:**  
- IOC enrichment and cross-case pivoting initiated

---

## Summary

These hypotheses guided the investigation from initial triage to full kill chain mapping. Each pivot point helped refine detection logic, escalate response, and build reusable playbooks for future phishing campaigns.
