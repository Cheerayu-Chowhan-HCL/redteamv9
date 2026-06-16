---
name: RedTeam V9 Report Interpreter
description: Post-engagement report quality checklist for RedTeam V9. Verifies CVSS coverage, finding completeness, evidence quality, and handles zero-finding edge cases.
---

# Report Interpretation — RedTeam V9

After generate_report completes, verify report quality before declaring the engagement done.
A report with missing CVSS scores, empty sections, or unflagged findings is not complete —
fix it and regenerate before finishing.

---

## Step 1: Call generate_report and Capture the Result

```python
r = generate_report(session_id)
# r contains: {"result": {"report_path": "...", "findings_count": N, ...}}

log_reasoning(session_id, "Orchestrator", "report_generated",
  '{"type":"observation","tool":"generate_report",
    "report_path":"[path]","findings_count":[N],
    "action":"running quality checklist"}')
```

Report location: `C:\users\chirayu\redteamv9\reports\{session_id}_report.html`

---

## Step 2: Quality Checklist

Work through every item. If any item fails, fix it before declaring done.

- [ ] **findings_count > 0** — result shows non-zero. If 0, see Step 4.
- [ ] **Executive Summary populated** — severity stat cards show non-zero counts (not all 0/0/0/0)
- [ ] **Every finding has a title** — no "[untitled]" or empty title fields
- [ ] **Every finding has a severity** — Critical / High / Medium / Low / Info (not blank)
- [ ] **Every finding has an endpoint** — no "[no endpoint]" or empty endpoint fields
- [ ] **Every finding has a CVSS vector** — no "N/A" or empty CVSS field anywhere
- [ ] **Evidence summaries present** — not empty, but sanitised (no raw payloads visible)
- [ ] **POC curl commands show `[PAYLOAD]`** — not real payload strings
- [ ] **Every finding has specific remediation** — actionable, not generic ("sanitise user input")
- [ ] **MCTS Confidence History chart present** — shows confidence evolution during engagement
- [ ] **Remediation Roadmap present** — ordered by priority with effort estimates

---

## Step 3: Fix Missing Fields

**Missing CVSS on a finding:**
```python
add_finding(session_id,
  title="[exact same title as existing finding]",
  severity="[correct severity]",
  endpoint="[endpoint]",
  evidence="[summary — no raw payloads]",
  cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # adjust vector to actual finding
  remediation="[specific, actionable fix]")
# Then regenerate:
generate_report(session_id)
```

**CVSS vector reference:**
- Auth bypass, RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → score 9.8 (Critical)
- SQLi (auth required): `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` → score 8.8 (High)
- Stored XSS: `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → score 6.1 (Medium)
- Reflected XSS: `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → score 6.1 (Medium)
- Missing HSTS: `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` → score 4.2 (Medium)
- Missing HttpOnly: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → score 5.3 (Medium)
- IDOR: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` → score 6.5 (Medium)
- Session fixation: `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` → score 7.1 (High)

**Generic remediation (must be made specific):**
```
Bad:  "Sanitise all user input"
Good: "Use parameterised queries (PreparedStatement) for the login handler at
       /j_spring_security_check. The username and password parameters are currently
       concatenated into the SQL query string."
```

**Low finding count (confirmed vulns during testing but count is wrong):**
Call `get_session_context(session_id)` and check `confirmed_findings`. If lower than expected,
call `add_finding` now for each vulnerability confirmed by tool output but not logged.

---

## Step 4: Handle Zero Findings

1. `get_session_context(session_id)` — check if add_finding calls were made during engagement
2. If findings confirmed in tool output but not logged: call `add_finding` for each, then regenerate
3. If genuinely no exploitable vulnerabilities found:
   ```python
   add_finding(session_id,
     title="Assessment Complete — No Exploitable Vulnerabilities Confirmed",
     severity="info",
     endpoint=target_url,
     evidence="Full 6-phase assessment completed. No exploitable vulnerabilities confirmed by tool results.",
     cvss="",
     remediation="Continue regular security testing cadence.")
   generate_report(session_id)
   ```

---

## CVSS 3.1 Severity Reference

| Score | Severity | Typical Examples |
|-------|----------|-----------------|
| 9.0–10.0 | **Critical** | RCE, full auth bypass, unauthenticated DB dump |
| 7.0–8.9 | **High** | SQL injection, stored XSS, IDOR with PII |
| 4.0–6.9 | **Medium** | Reflected XSS, CSRF, missing HSTS |
| 0.1–3.9 | **Low** | Missing cookie flags, info disclosure |
| 0.0 | **Info** | No direct security impact |

---

## Critical Finding Protocol (CVSS >= 9.0)

For any finding with CVSS >= 9.0, verify before calling generate_report:

1. Finding is logged with full CVSS vector string (not just a number)
2. Evidence field contains sanitised tool output confirming exploitation
3. Remediation is specific and actionable (not generic)
4. Log the critical confirmation:
```python
log_reasoning(session_id, "Orchestrator", "critical_confirmed",
  '{"type":"observation","finding":"[title]","cvss":[score],
    "note":"critical finding documented in report with full CVSS vector"}')
```

---

## Regeneration

Call `generate_report(session_id)` as many times as needed — it overwrites the previous file
and re-reads all findings from the database. There is no penalty for multiple calls.
Always call it one final time after all add_finding fixes are complete.

---

## Security Note on Report Content

The HTML report is sanitised before saving:
- Evidence fields contain summaries — not raw HTTP request/response bodies
- POC curl commands show `[PAYLOAD]` — not actual injection strings
- Cookie values are masked in all output

This is intentional. The report is safe to share with developers, management, and stakeholders.
