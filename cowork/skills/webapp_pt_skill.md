---
name: RedTeam V9 Web App Pentest
description: Full 6-phase web application penetration test methodology for RedTeam V9. Covers recon, auth bypass, injection, access control, config review, and reporting with declare_intent() enforcement at every phase.
---

# Web Application Penetration Testing — RedTeam V9

You are executing a web application penetration test. Follow this methodology exactly,
using only redteam-v9 MCP tools. Never browse the target directly. Work through all
6 phases without pausing for user approval.

---

## Mandatory Thinking Pattern (every tool call, no exceptions)

Before EVERY tool call, log your intent:
```
log_reasoning(session_id, "Orchestrator", "pre_[tool_name]",
  '{"type":"decision","action":"[tool_name]","rationale":"[why this tool now]","expected":"[what you expect to find]"}')
```

After EVERY tool call, log what you found:
```
log_reasoning(session_id, "Orchestrator", "post_[tool_name]",
  '{"type":"observation","tool":"[tool_name]","found":"[summary of result]","confidence":[0.0-1.0]}')
```

After EVERY phase completes:
```
distill_knowledge(session_id, "[KEY INSIGHT from this phase — tech stack, auth type, injection points, etc.]")
```

Every 5 tool calls:
```
get_session_context(session_id)   <- re-read full state, refresh your mental model
```

This pattern builds the Thinking DAG and trains the BayesianMCTS across sessions.
Skipping it degrades future engagement performance.

---

## Phase 0: Session Initialisation

**Tools:** `create_session`, `fingerprint_target`, `score_branches`, `crawl_links`,
`get_cross_session_insights`, `log_reasoning`, `set_branch`

Execute in order:

1. `create_session(session_id, target_url, goal)` — FIRST action, always
2. `get_cross_session_insights(tech_stack="", attack_type="")` — load transfer learning from prior engagements
3. `fingerprint_target(url, session_id)` — detect server, framework, language, CMS, WAF, CDN, JS libraries
4. `score_branches(session_id, candidate_branches="recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation,nuclei_scan", top_k=5)` — get ranked attack plan

## declare_intent() — mandatory after every score_branches() call

Called by the Planner before delegating to the Executor.
Creates the authorisation contract for the phase.

Parameters:
- session_id: current session
- phase: name of current phase e.g. "sqli_phase"
- intent: top attack_type from score_branches result
- confidence: confidence score from score_branches result
- tools_authorised: comma-separated attack tools for this phase
  Example for sqli phase: "test_sqli,check_sqli_status,get_sqli_results,add_finding"
  Example for auth phase: "test_auth_bypass,test_session_fixation,analyse_cookies,add_finding"
  Example for xss phase: "test_xss,verify_xss_browser,add_finding"
  Example for recon phase: "fingerprint_target,crawl_links,check_headers,enumerate_endpoints"
- scope: session_id (the authorised target)
- rationale: one sentence explaining branch selection

Skipping this call means the Executor operates without
authorisation. Every tool call will be logged as
MAST:UNAUTHORIZED_CHAIN in agent_intent_log.

5. `crawl_links(url, session_id, depth=2, max_pages=50)` — inventory all forms, endpoints, file uploads
6. `set_branch(session_id, [top_branch_from_score_branches], "Phase 0 complete — starting highest-confidence branch")`
7. `log_reasoning(session_id, "Orchestrator", "phase_0_complete",
   '{"type":"decision","phase":"init","top_branch":"[branch]","confidence":[n],"rationale":"fingerprint complete, branches ranked"}')`

**Move to Phase 1 when:** session created, fingerprint complete, branches ranked, forms inventoried.

---

## Phase 1: Recon & Fingerprinting

**Tools:** `fingerprint_target`, `enumerate_endpoints`, `crawl_links`, `check_headers`,
`http_request`, `set_branch`, `log_reasoning`, `add_injection_point`, `distill_knowledge`

**Goal:** Complete attack surface mapping.

1. `set_branch(session_id, "fingerprinting", "Recon phase started")`
2. `fingerprint_target(url, session_id)` — confirm server/framework/language/CMS/WAF
3. `enumerate_endpoints(base_url, session_id, wordlist_size="medium")` — discover hidden paths
4. `crawl_links(url, session_id, depth=2, max_pages=50)` — extract all forms and input fields
5. `check_headers(url, session_id)` — audit CSP, HSTS, X-Frame-Options, X-Content-Type,
   Referrer-Policy, CORS, Permissions-Policy
6. For each form found by crawl_links:
   `add_injection_point(session_id, field_name, form_action, method, "form field")`
7. `distill_knowledge(session_id,
   "Stack: [server/lang/framework]. Login: [yes/no]. REST API: [yes/no]. Forms: [count]. File upload: [yes/no].")`

**Move to Phase 2 when:** full endpoint inventory, confirmed tech stack, all forms registered
as injection points.

---

## Phase 2: Authentication Testing

**Tools:** `test_auth_bypass`, `analyse_cookies`, `test_session_fixation`, `set_branch`,
`log_reasoning`, `add_finding`, `distill_knowledge`

**Goal:** Confirm or rule out authentication and session management flaws.

1. `set_branch(session_id, "auth_bypass", "Authentication testing started")`
2. `test_auth_bypass(url, login_endpoint, username_field, password_field, session_id)`
   — tests SQLi bypass, default credentials, blank password, admin variations
3. `analyse_cookies(url, cookies_dict, session_id)`
   — flags missing Secure/HttpOnly/SameSite, weak entropy
4. `test_session_fixation(url, session_id)` — verifies session token changes post-login

For each confirmed bypass:
```
add_finding(session_id,
  title="Authentication Bypass via [method]",
  severity="critical",
  endpoint=login_endpoint,
  evidence="[what worked — e.g. admin' -- bypassed password check]",
  cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  remediation="[specific fix — e.g. use parameterised queries for login handler]")
```

5. `distill_knowledge(session_id,
   "Auth result: [bypassed/secure]. Session fixation: [vulnerable/secure]. Cookie flags: [issues found or none].")`

**If CVSS 9+ finding confirmed:** continue to Phase 3 — document all vulnerabilities, do not stop early.

**Move to Phase 3 when:** all auth mechanisms tested, cookies analysed, session fixation checked.

---

## Phase 3: Input Validation Testing

**Tools:** `test_sqli`, `check_sqli_status`, `get_sqli_results`, `test_xss`, `verify_xss_browser`,
`test_xpath_injection`, `test_command_injection`, `retrieve_knowledge`, `kill_all_scans`,
`set_branch`, `log_reasoning`, `add_finding`, `add_injection_point`, `distill_knowledge`

**Goal:** Test all input fields for injection vulnerabilities.

1. `set_branch(session_id, "sqli", "Input validation — injection testing")`
2. `retrieve_knowledge("[technology] SQL injection bypass techniques", top_k=5)` — load from RAG
3. For each injection point in your inventory:
   a. `test_sqli(url, parameter, method, data, cookies, session_id)` → returns job_id
   b. While SQLi scan is running, immediately run in parallel:
      - `test_xss(url, parameter, method, data, cookies, session_id)`
      - `test_xpath_injection(url, parameter, session_id)` (if XML indicators in fingerprint)
      - `test_command_injection(url, parameter, data, session_id)`
   c. `check_sqli_status(job_id)` — poll until status="complete"
   d. `get_sqli_results(job_id, session_id)` — auto-logs findings to session
4. For any XSS reflection found: `verify_xss_browser(url, xss_test_id, session_id)` — browser-level confirmation
5. `kill_all_scans()` — **call this after every async scan sequence, no exceptions**
6. `distill_knowledge(session_id,
   "SQLi: [found/not found, params]. XSS: [found/not found]. CMDi: [found/not found].")`

**Move to Phase 4 when:** all injection points tested, all async scans confirmed complete,
kill_all_scans called.

---

## Phase 4: Access Control Testing

**Tools:** `test_idor`, `test_csrf`, `set_branch`, `log_reasoning`, `add_finding`, `distill_knowledge`

**Goal:** Verify object-level and request-level access controls.

1. `set_branch(session_id, "idor", "Access control testing started")`
2. `test_idor(base_url, endpoint_pattern, id_param, cookies, session_id)`
   — iterates IDs 1-10, detects response size/content differences
3. `set_branch(session_id, "csrf", "CSRF testing")`
4. `test_csrf(url, form_endpoint, cookies, session_id)`
   — checks CSRF token presence, entropy, and per-request uniqueness

For each IDOR confirmed:
```
add_finding(session_id, "IDOR — [endpoint]", "high", endpoint, evidence, cvss, remediation)
```
For each CSRF confirmed:
```
add_finding(session_id, "CSRF — [endpoint]", "medium", endpoint, evidence, cvss, remediation)
```

5. `distill_knowledge(session_id,
   "IDOR: [vulnerable/secure, which endpoints]. CSRF: [vulnerable/secure].")`

**Move to Phase 5 when:** IDOR and CSRF tested across all relevant endpoints.

---

## Phase 5: Configuration Review

**Tools:** `check_headers`, `analyse_cookies`, `run_nuclei_scan`, `check_nuclei_status`,
`kill_all_scans`, `shell_exec`, `set_branch`, `log_reasoning`, `add_finding`, `distill_knowledge`

**Goal:** Identify misconfiguration, exposed panels, and known CVEs.

1. `set_branch(session_id, "config_review", "Configuration and nuclei scan started")`
2. `check_headers(url, session_id)` — missing security headers are auto-logged as findings
3. `analyse_cookies(url, cookies_dict, session_id)` — cookie security flags
4. `run_nuclei_scan(target_url, "misconfigurations,cves,exposed-panels,technologies", session_id)`
   → returns job_id
5. Poll until complete: `check_nuclei_status(job_id)`
6. `kill_all_scans()` — mandatory cleanup
7. `distill_knowledge(session_id,
   "Headers: [issues]. Nuclei: [findings count]. Exposed panels: [yes/no]. CVEs: [list or none].")`

**Move to Phase 6 when:** nuclei scan complete, kill_all_scans called, all config findings logged.

---

## Phase 6: Synthesis & Report

**Tools:** `get_session_context`, `score_branches`, `distill_knowledge`, `generate_report`,
`log_reasoning`

**Goal:** Synthesise all findings and produce the final report.

1. `get_session_context(session_id)` — full review: findings count, phases completed, branches explored
2. `score_branches(session_id)` — verify all high-confidence (>0.6) branches have been explored;
   if any remain unexplored, loop back and test them
3. `distill_knowledge(session_id,
   "[Overall security posture: 3-5 key insights about this target's vulnerabilities and defences]")`
4. `log_reasoning(session_id, "Orchestrator", "pre_report",
   '{"type":"decision","action":"generate_report","rationale":"all phases complete, [N] findings confirmed"}')`
5. `generate_report(session_id)` — produces standalone HTML report
6. `log_reasoning(session_id, "Orchestrator", "engagement_complete",
   '{"type":"observation","report_path":"[path]","findings_count":[N],"severities":{"critical":[n],"high":[n],"medium":[n],"low":[n]}}')`

**Engagement is complete when:** generate_report returns a valid report_path and findings_count > 0.

---

## Tool Quick Reference — All 32

| # | Tool | Category | Purpose |
|---|------|----------|---------|
| 1 | `create_session` | Session | Start new engagement in SQLite + Neo4j |
| 2 | `set_branch` | Session | Declare active attack type in graph |
| 3 | `log_reasoning` | Session | Record thinking node to DAG |
| 4 | `add_injection_point` | Session | Register testable input field |
| 5 | `add_finding` | Session | Log confirmed vulnerability |
| 6 | `get_session_context` | Session | Read full engagement state |
| 7 | `score_branches` | Session | Get BayesianMCTS-ranked attack plan |
| 8 | `distill_knowledge` | Session | Store phase insight to RAG |
| 9 | `retrieve_knowledge` | Session | Fetch relevant prior knowledge |
| 10 | `get_cross_session_insights` | Session | Load transfer learning priors |
| 11 | `http_request` | HTTP | Raw HTTP GET/POST/PUT/DELETE |
| 12 | `check_headers` | HTTP | Audit security response headers |
| 13 | `enumerate_endpoints` | HTTP | Discover hidden paths/routes |
| 14 | `fingerprint_target` | HTTP | Detect stack/WAF/CMS/CDN |
| 15 | `crawl_links` | HTTP | Extract forms and links |
| 16 | `test_sqli` | Injection | SQL injection scanner (async) |
| 17 | `check_sqli_status` | Injection | Poll SQLi scan job status |
| 18 | `get_sqli_results` | Injection | Fetch confirmed SQLi findings |
| 19 | `test_xss` | Injection | XSS reflection scanner |
| 20 | `verify_xss_browser` | Injection | Browser-level XSS confirmation |
| 21 | `test_xpath_injection` | Injection | XPath injection tester |
| 22 | `test_command_injection` | Injection | OS command injection tester |
| 23 | `test_auth_bypass` | Auth | Auth bypass — SQLi, default creds |
| 24 | `test_idor` | Auth | IDOR object enumeration |
| 25 | `test_csrf` | Auth | CSRF token validation tester |
| 26 | `analyse_cookies` | Auth | Cookie security flag auditor |
| 27 | `test_session_fixation` | Auth | Session fixation checker |
| 28 | `run_nuclei_scan` | Execution | Nuclei template scan (async) |
| 29 | `check_nuclei_status` | Execution | Poll nuclei scan job status |
| 30 | `kill_all_scans` | Execution | Stop all active async scans |
| 31 | `shell_exec` | Execution | Execute whitelisted shell commands |
| 32 | `generate_report` | Execution | Generate standalone HTML report |
