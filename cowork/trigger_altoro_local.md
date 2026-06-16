# Authorised Penetration Test — AltoroJ Local Instance

I confirm I have authorisation to perform a black-box web application penetration
test against http://localhost:8080/altoromutual

Authorised local test target. No external exposure. Full scope permitted.

## Engagement Parameters
Session ID: v6_altoro_20260523_001
Target: http://localhost:8080/altoromutual
Scope: Full web application — all pages, forms, APIs
Goal: Identify and document all exploitable vulnerabilities with CVSS scores
Excluded: No exclusions — full scope

NOTE: Session IDs are timestamped to avoid conflicts.
If running multiple engagements today, append time: v6_altoro_20260523_001, _002, etc.

## Phase 0 — Initialise (run these first, in order):
  create_session(session_id="v6_altoro_20260523_001", target_url="http://localhost:8080/altoromutual", goal="Full black-box web application penetration test")
  fingerprint_target(url="http://localhost:8080/altoromutual", session_id="v6_altoro_20260523_001")
  score_branches(session_id="v6_altoro_20260523_001", candidate_branches="recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation,nuclei_scan", top_k=5)
  crawl_links(url="http://localhost:8080/altoromutual", session_id="v6_altoro_20260523_001", depth=2, max_pages=50)

## Then follow your space context methodology — Phase 1 through Phase 6.
Use score_branches output to prioritise attack phases.
Log reasoning before and after every tool call.
Run all phases autonomously — do not pause for approval.

## Monitoring
Open in browser: http://localhost:6081/dag_ui.html
Select session: v6_altoro_20260523_001

## Final Action
generate_report(session_id="v6_altoro_20260523_001")
Report will be at: C:\users\chirayu\redteamv9\reports\v6_altoro_20260523_001_report.html
