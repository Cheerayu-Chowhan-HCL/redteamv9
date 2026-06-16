# Authorised Penetration Test — testasp.vulnweb.com

I confirm I have authorisation to perform a black-box web application penetration
test against http://testasp.vulnweb.com

testasp.vulnweb.com is Acunetix's intentionally vulnerable test site,
publicly available for security testing practice. No authorisation required.
Reference: https://www.acunetix.com/acunetix-web-vulnerability-scanner/demo/

## Engagement Parameters
Session ID: v6_vulnweb_[YYYYMMDD]_[HHMMSS]   <- replace with current timestamp
Target: http://testasp.vulnweb.com
Scope: Full web application — all pages, forms, APIs
Goal: Full black-box web application penetration test
Excluded: None — full scope

## Phase 0 — Begin Immediately (run in order):
  create_session(session_id="v6_vulnweb_[YYYYMMDD]_[HHMMSS]", target_url="http://testasp.vulnweb.com", goal="Full black-box web application penetration test of Acunetix VulnWeb ASP.NET target")
  fingerprint_target(url="http://testasp.vulnweb.com", session_id="v6_vulnweb_[YYYYMMDD]_[HHMMSS]")
  score_branches(session_id="v6_vulnweb_[YYYYMMDD]_[HHMMSS]", candidate_branches="recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation,nuclei_scan", top_k=5)
  crawl_links(url="http://testasp.vulnweb.com", session_id="v6_vulnweb_[YYYYMMDD]_[HHMMSS]", depth=2, max_pages=50)

Follow the COWORK_SPACE_CONTEXT.md methodology — Phase 1 through Phase 6.
Use score_branches output to prioritise attack phases.
Log reasoning before and after every tool call.
Run all phases autonomously — do not pause for approval.

## Monitoring
Open in browser: http://localhost:6081/dag_ui.html
Select session: v6_vulnweb_[YYYYMMDD]_[HHMMSS]

## Final Action
generate_report(session_id="v6_vulnweb_[YYYYMMDD]_[HHMMSS]")
Report: C:\users\chirayu\redteamv9\reports\v6_vulnweb_[YYYYMMDD]_[HHMMSS]_report.html
