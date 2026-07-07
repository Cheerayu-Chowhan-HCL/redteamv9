---
name: Pentest Report Quality
description: Report verification and quality checklist for penetration test findings. Triggers after generate_report is called. Ensures every finding has CVSS scores, POC commands, and remediation steps before declaring the engagement complete.
trigger: auto
---

# Report Quality Verification — RedTeam V9

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

---

## Step 2: Quality Checklist

Work through every item. Fix any failure before declaring done.

- [ ] **findings_count >= 0** — zero is valid if the target had no vulnerabilities
- [ ] **Executive Summary populated** — severity stat cards reflect actual findings
- [ ] **Every finding has a title** — no "[untitled]" or empty title fields
- [ ] **Every finding has a severity** — Critical / High / Medium / Low / Info
- [ ] **Every finding has an endpoint** — the actual discovered endpoint, not a placeholder
- [ ] **Every finding has a CVSS vector** — the full vector string, not just a score or "N/A"
- [ ] **Evidence summaries present** — tool output summary, sanitised (no raw payloads)
- [ ] **POC curl commands show `[PAYLOAD]`** — not actual injection strings
- [ ] **Every finding has specific remediation** — names the exact endpoint and fix required
- [ ] **MCTS Confidence History chart present** — shows confidence evolution
- [ ] **Remediation Roadmap present** — ordered by CVSS priority with effort estimates

---

## Step 3: Fix Missing Fields

**Missing CVSS:**
```python
add_finding(session_id,
  title="[exact same title as existing finding]",
  severity="[correct severity]",
  endpoint="[the discovered endpoint]",
  evidence="[sanitised tool output summary]",
  cvss="[correct CVSS vector — see table below]",
  remediation="[specific fix: names the endpoint, the vulnerable component, and the correct mitigation]")
generate_report(session_id)  # safe to call multiple times — overwrites previous file
```

**CVSS vector reference by finding type:**

| Finding Type | CVSS Vector | Score | Severity |
|-------------|------------|-------|----------|
| Auth bypass / RCE (unauthenticated) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |
| SQLi (authenticated) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | High |
| SQLi (unauthenticated) | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | Critical |
| Stored XSS | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | Medium |
| Reflected XSS | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | Medium |
| IDOR (horizontal) | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | 6.5 | Medium |
| CSRF | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` | 4.3 | Medium |
| Session fixation | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` | 7.1 | High |
| Missing HSTS | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N` | 4.2 | Medium |
| Missing CSP | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | Medium |
| Missing HttpOnly flag | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 | Medium |
| Info disclosure | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 | Medium |

**Remediation must be specific:**
```
Insufficient: "Sanitise user input"
Sufficient:   "Replace string concatenation with parameterised queries at the
               authentication handler [discovered endpoint]. The [discovered parameter]
               field is directly concatenated into the SQL query string."
```

**Low finding count — confirm nothing was missed:**
```python
get_session_context(session_id)
# Check: confirmed_findings count vs. add_finding calls made
# If lower than expected, call add_finding for each tool-confirmed vulnerability not yet logged
```

---

## Step 4: Handle Zero Findings

Zero findings after a full 6-phase engagement is a valid result. Verify:

1. `get_session_context(session_id)` — confirm all phases ran and injection points were tested
2. If findings were confirmed by tool output but not logged: call `add_finding` now, regenerate
3. If genuinely no vulnerabilities found:
   ```python
   add_finding(session_id,
     title="Assessment Complete — No Exploitable Vulnerabilities Confirmed",
     severity="info",
     endpoint=target_url,
     evidence="Full 6-phase assessment completed. All discovered parameters tested. No exploitable vulnerabilities confirmed by tool results.",
     cvss="",
     remediation="Continue regular security testing cadence.")
   generate_report(session_id)
   ```

---

## CVSS 3.1 Severity Reference

| Score | Severity | Description |
|-------|----------|-------------|
| 9.0–10.0 | **Critical** | Unauthenticated RCE, full auth bypass, unauthenticated data dump |
| 7.0–8.9 | **High** | Authenticated SQLi, stored XSS, session fixation with full account takeover |
| 4.0–6.9 | **Medium** | Reflected XSS, CSRF, IDOR, missing HSTS, weak session tokens |
| 0.1–3.9 | **Low** | Missing cookie flags, verbose error messages, minor info disclosure |
| 0.0 | **Info** | No direct security impact — observation only |

---

## Critical Finding Protocol (CVSS >= 9.0)

Before calling generate_report, verify each Critical finding has:

1. Full CVSS vector string (not just a number)
2. Evidence field with sanitised tool output confirming exploitation
3. Specific remediation naming the exact endpoint and required fix
4. Log the confirmation:
```python
log_reasoning(session_id, "Orchestrator", "critical_confirmed",
  '{"type":"observation","finding":"[title]","cvss":[score],
    "note":"critical finding documented with full CVSS vector and specific remediation"}')
```

---

## Regeneration

Call `generate_report(session_id)` as many times as needed. Each call overwrites the
previous file and re-reads all findings from the database. Always call once more after
completing all add_finding fixes.

---

## Report Security Note

The HTML report is sanitised before saving:
- Evidence fields contain summaries — not raw HTTP request/response bodies
- POC curl commands show `[PAYLOAD]` — not actual injection strings
- Cookie values are masked

The report is safe to share with developers, management, and stakeholders.
