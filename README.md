# KC7 Threat Hunting Journal — README

## Overview
# 🛡️ KC7 Threat Hunting Journal

Welcome to my KC7 Threat Hunting Journal — a modular, case-based repository designed to document, analyze, and share threat investigations with clarity, repeatability, and tactical insight.

This repo blends technical rigor with storytelling, enabling security teams and incident responders to trace adversary behavior across the kill chain while building reusable artifacts for onboarding, detection engineering, and strategic reporting.

---

## 📁 Repo Structure

```plaintext
├─ README.md                     # (this file)
├─ cases/
│  ├─ YYYY-MM-DD-slug/           # Case folders named by date and short slug
│  │  ├─ README.md               # Case summary, timeline, and analysis overview
│  │  ├─ timeline.md             # Chronological event log with queries and evidence
│  │  ├─ analysis.md             # MITRE ATT&CK mapping and impact summary
│  │  ├─ artifacts/              # Screenshots, email headers, IOC lists, etc.
│  │  ├─ evidence/               # Linked markdown files for each evidence ID
│  │  └─ summary.md              # Executive summary for leadership or reporting
```

## 🧠 Purpose

This repo was created to:

-  Document threat cases with clarity and tactical depth
-  Map adversary behavior to MITRE ATT&CK techniques
-  Build reusable templates for detection and response
-  Enable onboarding through annotated timelines and queries
-  Honor the legacy of service and resilience through operational clarity

## Case template (per-case README)
Each case folder should contain a README.md using this structure:

- Title
- Short summary (1–2 lines)
- Status (open / in analysis / closed / remediated)
- Owner / Analyst
- Timeline (chronological events with timestamps)
- Evidence & queries (saved queries and how to run them)
- Hypotheses (enumerated, testable)
- Analysis (step-by-step observations and findings)
- Conclusion & action taken
- References / IOC list
- Lessons learned / next steps

Example (abridged)
```
Title: Phishing -> Credential Harvesting (2025-01-15)
Summary: User reported suspicious login prompt after clicking email link.
Status: Closed
Owner: analyst@example.com

Timeline:
- 2025-01-15 08:12 UTC: Phishing email delivered to user@example.com (mail headers saved)
- 2025-01-15 08:20 UTC: User clicked link; redirected to credential page
- 2025-01-15 08:24 UTC: Suspicious outbound DNS queries to short-lived domain

Evidence & queries:
- Mail headers: artifacts/mail_headers.eml
- Web proxy query (KQL):
    ```
    ProxyLogs
    | where Timestamp >= datetime(2025-01-15 08:00:00) and Timestamp <= datetime(2025-01-15 09:00:00)
    | where Url contains "suspicious-domain.com" or Host contains "short.ly"
    ```
- Endpoint process chain (EDR):
    - Parent: outlook.exe -> child: rundll32.exe -> child: powershell.exe

Hypotheses:
1. User submitted credentials to attacker-controlled page (high priority).
2. Email included link that triggered downloader (medium).
3. Domain is short-lived/part of phishing infrastructure (low).

Analysis:
- Mail header analysis shows SPF/DKIM fail for sending domain -> supports phishing.
- Web proxy logs show 3 POSTs to credential URL; POST body contains form fields matching login.
- EDR process tree shows no persistent payload; no post-exploitation lateral movement observed.

Conclusion & actions:
- Credentials rotated for affected user, MFA enforced.
- Blocked domain at proxy and DNS.
- Notified mail provider and filed takedown.
- Case closed.

IOCs:
- suspicious-domain.com
- 203.0.113.45

Lessons Learned:
- Phishing emails with failed SPF/DKIM should trigger automated triage or quarantine.
- Users are still vulnerable to credential harvesting via realistic job-themed lures—targeted awareness training is needed.
- Short-lived domains used in phishing campaigns often evade static blocklists; dynamic DNS monitoring should be prioritized.
- Endpoint visibility into process chains (e.g., Outlook → rundll32 → PowerShell) is critical for early detection.
- MFA significantly reduced post-compromise impact—reinforces its role as a frontline defense.
- Takedown coordination with mail providers can be accelerated with pre-approved workflows and templates.
```

## 📄 Licensing & Attribution

This repository is released under a dual-license model to support both technical reuse and educational sharing:

- **MIT License** applies to all detection logic, queries, and code snippets (e.g., KQL, Sigma, YARA).  
  You are free to use, modify, and distribute these components with attribution.

- **Creative Commons Attribution 4.0 International (CC BY 4.0)** applies to all documentation, timelines, analysis, and training artifacts.  
  You may share and adapt the content for any purpose, provided you give appropriate credit.

---

### External Attribution

This repository references external frameworks and standards for educational and operational use:

- **MITRE ATT&CK®** is a registered trademark of The MITRE Corporation.  
  Tactic and technique mappings are based on the [MITRE ATT&CK Framework](https://attack.mitre.org/).

- **KC7** is a project maintained by the KC7 Foundation.  
  This repository does not redistribute KC7 content. For official materials, visit [KC7 Foundation on GitHub](https://github.com/KC7-Foundation).

- **Microsoft KQL** is governed by Microsoft’s product terms.  
  For usage details, see [Microsoft Terms of Use](https://learn.microsoft.com/en-us/legal/license/terms-of-use).

---

If you plan to reuse or distribute any part of this content, please ensure proper attribution and verify licensing terms with the original sources.
