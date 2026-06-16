# Authorised Penetration Test — {{TARGET_NAME}}

I confirm I have authorisation to perform a black-box web application penetration
test against {{TARGET_URL}}

{{AUTHORISATION_NOTE}}

## Engagement Parameters
Session ID: {{SESSION_ID}}
Target: {{TARGET_URL}}
Scope: {{SCOPE}}
Goal: {{GOAL}}
Excluded: {{EXCLUSIONS}}

## How to generate SESSION_ID (no conflicts):
  Format: v6_{shortname}_{YYYYMMDD}_{HHMMSS}
  Example: v6_myapp_20260523_143022
  Generate from current timestamp at engagement start.

## Phase 0 — Initialise (run these first, in order):
  create_session(session_id="{{SESSION_ID}}", target_url="{{TARGET_URL}}", goal="{{GOAL}}")
  fingerprint_target(url="{{TARGET_URL}}", session_id="{{SESSION_ID}}")
  score_branches(session_id="{{SESSION_ID}}", candidate_branches="recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation,nuclei_scan", top_k=5)
  crawl_links(url="{{TARGET_URL}}", session_id="{{SESSION_ID}}", depth=2, max_pages=50)

## Then follow your space context methodology — Phase 1 through Phase 6.
Use score_branches output to prioritise attack phases.
Log reasoning before and after every tool call.
Run all phases autonomously — do not pause for approval.

## Monitoring
Open in browser: http://localhost:6081/dag_ui.html
Select session: {{SESSION_ID}}

## Final Action
generate_report(session_id="{{SESSION_ID}}")
Report will be at: C:\users\chirayu\redteamv9\reports\{{SESSION_ID}}_report.html

---
## Template Instructions (delete before sending to Cowork)

Replace these placeholders before using:
  {{TARGET_NAME}}       — Short display name e.g. "My App v2"
  {{TARGET_URL}}        — Full URL e.g. http://myapp.example.com
  {{SESSION_ID}}        — Auto-generated e.g. v6_myapp_20260523_143022
  {{GOAL}}              — e.g. "Full black-box web application penetration test"
  {{SCOPE}}             — e.g. "Full application — all pages, forms, APIs"
  {{EXCLUSIONS}}        — e.g. "None" or "/admin — not in scope"
  {{AUTHORISATION_NOTE}} — e.g. "This is an Acunetix test target, no auth required." or
                            "Written authorisation from client on file, engagement ID: XXXX"
