# RedTeam V9 — Cowork Commands

## /pentest
Starts a full black-box penetration test engagement.

**Usage:** `/pentest target=URL session=SESSION_ID [goal=GOAL]`

Session ID format: `v6_{shortname}_{YYYYMMDD}_{HHMMSS}` — auto-generate from current timestamp.

**Examples:**
```
/pentest target=http://localhost:8080/altoromutual session=v6_altoro_20260523_143022
/pentest target=http://testasp.vulnweb.com session=v6_vulnweb_20260523_091545 goal="API security assessment"
```

**Expanded prompt template (paste this, substituting values):**

---
I confirm I have authorisation to perform a black-box web application penetration
test against {{TARGET_URL}}

Session ID: {{SESSION_ID}}
Target: {{TARGET_URL}}
Goal: {{GOAL}}
Scope: Full web application — all pages, forms, APIs accessible from the target root

Your role: Orchestrator agent. All methodology is in your space context (COWORK_SPACE_CONTEXT.md).

Begin immediately with these Phase 0 actions:
1. create_session(session_id="{{SESSION_ID}}", target_url="{{TARGET_URL}}", goal="{{GOAL}}")
2. fingerprint_target(url="{{TARGET_URL}}", session_id="{{SESSION_ID}}")
3. score_branches(session_id="{{SESSION_ID}}", candidate_branches="recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation,nuclei_scan", top_k=5)
4. crawl_links(url="{{TARGET_URL}}", session_id="{{SESSION_ID}}", depth=2, max_pages=50)

Then follow the 6-phase methodology in your space context through all phases.
Log reasoning before and after every tool call.
Run all phases autonomously — do not pause for approval.

Monitoring: http://localhost:6081/dag_ui.html (open this now — select session {{SESSION_ID}} from dropdown)

Final action: generate_report(session_id="{{SESSION_ID}}")
Then report the file path and a summary of key findings.
---

---

## /status
Check current engagement status.

**Usage:** `/status session=SESSION_ID`

**Expands to:**
```
Call get_session_context(session_id="{{SESSION_ID}}") and summarise:
- How many findings have been confirmed (and their severities)
- Which phases have been completed
- What the current active branch is
- Top 3 MCTS-ranked remaining attack branches
```

---

## /report
Generate final report immediately (even if phases not complete).

**Usage:** `/report session=SESSION_ID`

**Expands to:**
```
Call generate_report(session_id="{{SESSION_ID}}")
Open: C:\users\chirayu\redteamv9\reports\{{SESSION_ID}}_report.html
Summarise: finding count by severity, top 3 findings, CVSS scores
```

---

## /flush
Clear a session from all databases.

**Usage:** `/flush session=SESSION_ID`

**Expands to:**
```
Run from C:\users\chirayu\redteamv9:
  python flush_dbs.py --session {{SESSION_ID}}
Confirm: SQLite rows deleted, Neo4j nodes deleted.
```

---

## /dag
Open the live monitoring dashboard.

**Expands to:**
```
Open http://localhost:6081/dag_ui.html in browser.
Select session from dropdown to view:
  - Left panel: Thinking DAG (purple — reasoning steps, hypotheses)
  - Right panel: Attack DAG (blue/red — nodes, findings, branches)
```

---

## /targets
List available pre-verified pentest targets.

**Expands to:**
```
AltoroJ local:     http://localhost:8080/altoromutual     (Docker: altoro)
VulnWeb ASP.NET:   http://testasp.vulnweb.com             (Public Acunetix target)
demo.testfire.net: http://demo.testfire.net               (HCL — currently DOWN)
```

---

## Session ID Generation

Always generate session IDs programmatically to avoid conflicts:

```python
from datetime import datetime
shortname = "altoro"  # or "vulnweb", "testfire", etc.
session_id = f"v6_{shortname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
# e.g. v6_altoro_20260523_143022
```

Or derive from the current timestamp when typing the trigger:
- Check current time ? `v6_altoro_{YYYYMMDD}_{HHMMSS}`
- This guarantees uniqueness across multiple same-day engagements.
