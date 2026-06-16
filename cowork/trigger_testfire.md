# Authorised Penetration Test — demo.testfire.net

I confirm I have authorisation to perform a black-box web application penetration
test against http://demo.testfire.net

## Engagement Parameters
Session ID: v6_testfire_20260522_001
Target: http://demo.testfire.net
Scope: Full web application — all pages, forms, APIs
Goal: Identify and document all exploitable vulnerabilities with CVSS scores
Excluded: No exclusions — full scope

## Your Instructions

Read these skill files first:
- C:\users\chirayu\redteamv9\skills\webapp_pt_skill.md
- C:\users\chirayu\redteamv9\skills\cowork_orchestrator_skill.md
- C:\users\chirayu\redteamv9\skills\thinking_pattern_skill.md

Then begin the engagement autonomously:

Phase 0 — Initialise:
  create_session(session_id="v6_testfire_20260522_001", target_url="http://demo.testfire.net", goal="Full black-box web application penetration test")
  fingerprint_target(url="http://demo.testfire.net", session_id="v6_testfire_20260522_001")
  score_branches(session_id="v6_testfire_20260522_001", candidate_branches="recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation")
  crawl_links(url="http://demo.testfire.net", session_id="v6_testfire_20260522_001", depth=2, max_pages=50)

Then follow the skill file methodology — Phase 1 through Phase 6.
Use score_branches output to prioritise your attack phases.
Log reasoning before and after every tool call.
Run all phases autonomously — do not pause for approval.

Monitoring: http://localhost:6081/dag_ui.html (open this in your browser now)

Final action: generate_report(session_id="v6_testfire_20260522_001")
Then tell me the report path and key findings summary.
