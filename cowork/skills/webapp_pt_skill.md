---
name: WebApp Pentest Methodology
description: Full 6-phase web application penetration testing methodology. Triggers when user starts a pentest, mentions a target URL, or asks to test a web application. Covers recon, auth bypass, injection testing, access control, config review and report generation using redteam-v9 MCP tools.
trigger: slash command + auto
---

# Web Application Penetration Testing — RedTeam V9

You are executing a web application penetration test. You know NOTHING about the target
except the URL. Every fact about the application must be discovered through tool calls.
Never assume paths, parameters, frameworks, or vulnerabilities exist — find them first.
Work through all 6 phases without pausing for user approval.

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
distill_knowledge(session_id, "[KEY INSIGHT from this phase]")
score_branches(session_id, candidate_branches="recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation,nuclei_scan", top_k=5)
```
Re-scoring after every phase is mandatory — your target map grows with each phase and
the MCTS priors must be updated to reflect what you actually found.

Every 5 tool calls:
```
get_session_context(session_id)   <- re-read full state, refresh your mental model
```

---

## Phase 0: Session Initialisation

**Tools:** `create_session`, `fingerprint_target`, `score_branches`, `crawl_links`,
`get_cross_session_insights`, `log_reasoning`, `set_branch`

Execute in order with ONLY the URL provided. Do not assume anything about the target.

1. `create_session(session_id, target_url, goal)` — FIRST action, always
2. `get_cross_session_insights(tech_stack="", attack_type="")` — load transfer learning priors
3. `fingerprint_target(url, session_id)` — discover server, framework, language, WAF, CDN
   You will not know the tech stack until this returns. Do not guess.
4. `score_branches(session_id, candidate_branches="recon,sqli,xss,auth_bypass,idor,csrf,xpath_injection,headers,cookies,session_fixation,nuclei_scan", top_k=5)`
   The MCTS uses the fingerprint result to weight branches — always run after fingerprint.

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

5. `crawl_links(url, session_id, depth=2, max_pages=50)` — discover all forms and endpoints
   You will not know what pages or forms exist until this returns.
6. `set_branch(session_id, [top_branch_from_score_branches], "Phase 0 complete")`
7. `log_reasoning(session_id, "Orchestrator", "phase_0_complete",
   '{"type":"decision","phase":"init","top_branch":"[branch]","confidence":[n],"rationale":"fingerprint and crawl complete, branches now scored on real data"}')`

**Move to Phase 1 when:** session created, fingerprint complete, branches scored on real data,
forms and endpoints inventoried.

---

## Phase 1: Recon & Fingerprinting

**Tools:** `fingerprint_target`, `enumerate_endpoints`, `crawl_links`, `check_headers`,
`http_request`, `set_branch`, `log_reasoning`, `add_injection_point`, `distill_knowledge`

**Goal:** Complete attack surface mapping. You build your target map here — nothing is assumed.

1. `set_branch(session_id, "fingerprinting", "Recon phase started")`
2. `fingerprint_target(url, session_id)` — confirm technology details from Phase 0
3. `enumerate_endpoints(base_url, session_id, wordlist_size="medium")` — discover hidden paths
   Use the tech stack fingerprint result to select relevant wordlist segments.
4. `crawl_links(url, session_id, depth=2, max_pages=50)` — extract all forms and input fields
5. `check_headers(url, session_id)` — audit security headers: CSP, HSTS, X-Frame-Options,
   X-Content-Type, Referrer-Policy, CORS, Permissions-Policy
6. For each form found by crawl_links:
   `add_injection_point(session_id, field_name, form_action, method, "form field")`
   Register every discovered input — do not skip any.
7. `distill_knowledge(session_id,
   "Stack: [what fingerprint found]. Auth endpoint discovered: [yes/no — endpoint if yes]. Input fields: [count and locations].")`

**After phase:** Re-score branches with `score_branches` — your crawl results change the priors.

**Move to Phase 2 when:** full endpoint inventory done, all discovered forms registered as
injection points. If no forms found, skip Phase 2 auth and move to Phase 3.

---

## Phase 2: Authentication Testing

**Condition:** Only execute this phase if crawl_links discovered an authentication endpoint
(a form with credential-style fields, or an API auth endpoint). If no such endpoint was
found, log the skip and proceed to Phase 3.

**Tools:** `test_auth_bypass`, `analyse_cookies`, `test_session_fixation`, `set_branch`,
`log_reasoning`, `add_finding`, `distill_knowledge`

**Goal:** Test any discovered authentication endpoint for bypass and session flaws.

1. `set_branch(session_id, "auth_bypass", "Authentication testing started")`
2. For each discovered authentication endpoint:
   `test_auth_bypass(url, discovered_login_endpoint, discovered_username_field, discovered_password_field, session_id)`
   Only use field names actually found by crawl_links. Do not guess parameter names.
3. `analyse_cookies(url, cookies_dict, session_id)` — audit cookies from crawled responses
4. `test_session_fixation(url, session_id)` — test session token regeneration post-authentication

For each confirmed bypass:
```
add_finding(session_id,
  title="Authentication Bypass — [method used]",
  severity="critical",
  endpoint=[discovered endpoint],
  evidence="[tool output confirming bypass]",
  cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  remediation="[specific fix for this endpoint and technique]")
```

5. `distill_knowledge(session_id,
   "Auth result: [bypassed/secure/not tested — reason]. Session fixation: [result]. Cookie issues: [list or none].")`

**If CVSS 9+ confirmed:** continue to Phase 3 — document all vulnerabilities, do not stop early.

**Move to Phase 3 when:** all discovered authentication endpoints tested.

---

## Phase 3: Input Validation Testing

**Condition:** Only test parameters actually discovered in Phases 0–1. Do not guess or
invent parameter names. If no input fields were found, log it and skip to Phase 4.

**Tools:** `test_sqli`, `check_sqli_status`, `get_sqli_results`, `test_xss`, `verify_xss_browser`,
`test_xpath_injection`, `test_command_injection`, `retrieve_knowledge`, `kill_all_scans`,
`set_branch`, `log_reasoning`, `add_finding`, `add_injection_point`, `distill_knowledge`

**Goal:** Test all discovered input fields for injection vulnerabilities.

1. `set_branch(session_id, "sqli", "Injection testing — parameters from discovery phase")`
2. `retrieve_knowledge("[discovered technology] injection bypass techniques", top_k=5)`
   Query must use the actual tech stack discovered by fingerprint_target.
3. For each injection point registered in Phase 0–1:
   a. `test_sqli(url, discovered_parameter, method, data, cookies, session_id)` → job_id
   b. While scan runs, in parallel for the same discovered parameter:
      - `test_xss(url, discovered_parameter, method, data, cookies, session_id)`
      - `test_xpath_injection(url, discovered_parameter, session_id)`
        (only if XML/SOAP indicators found in fingerprint)
      - `test_command_injection(url, discovered_parameter, data, session_id)`
   c. `check_sqli_status(job_id)` — poll until complete
   d. `get_sqli_results(job_id, session_id)` — auto-logs to session
4. For any XSS confirmed: `verify_xss_browser(url, xss_test_id, session_id)`
5. `kill_all_scans()` — mandatory after every async sequence
6. `distill_knowledge(session_id, "Injection results: [per-parameter summary — found or not found].")`

**Move to Phase 4 when:** all discovered injection points tested, kill_all_scans called.

---

## Phase 4: Access Control Testing

**Condition:** Only test endpoints and IDs actually discovered in Phases 0–1.
If no ID-bearing endpoints were found, log it and move to Phase 5.

**Tools:** `test_idor`, `test_csrf`, `set_branch`, `log_reasoning`, `add_finding`, `distill_knowledge`

**Goal:** Verify object-level and request-level access controls on discovered endpoints.

1. `set_branch(session_id, "idor", "IDOR testing on discovered endpoints")`
2. For each discovered endpoint that contains an ID parameter:
   `test_idor(base_url, discovered_endpoint_pattern, discovered_id_param, cookies, session_id)`
3. `set_branch(session_id, "csrf", "CSRF testing on discovered forms")`
4. For each discovered form endpoint:
   `test_csrf(url, discovered_form_endpoint, cookies, session_id)`

For each confirmed vulnerability: `add_finding(...)` with appropriate severity and CVSS.

5. `distill_knowledge(session_id, "IDOR: [result per endpoint]. CSRF: [result per form].")`

**Move to Phase 5 when:** IDOR and CSRF tested on all relevant discovered endpoints.

---

## Phase 5: Configuration Review

**Tools:** `check_headers`, `analyse_cookies`, `run_nuclei_scan`, `check_nuclei_status`,
`kill_all_scans`, `shell_exec`, `set_branch`, `log_reasoning`, `add_finding`, `distill_knowledge`

**Goal:** Identify misconfiguration, exposed panels, and known CVEs. Discovery-driven —
nuclei templates find what exists, not what you expect.

1. `set_branch(session_id, "config_review", "Configuration audit and automated scan")`
2. `check_headers(url, session_id)` — missing security headers auto-logged as findings
3. `analyse_cookies(url, cookies_dict, session_id)` — cookie security flags
4. `run_nuclei_scan(target_url, "misconfigurations,cves,exposed-panels,technologies", session_id)`
   → returns job_id
5. `check_nuclei_status(job_id)` — poll until complete
6. `kill_all_scans()` — mandatory cleanup
7. `distill_knowledge(session_id,
   "Headers: [list issues or 'all present']. Nuclei: [finding count]. Any CVEs: [list or none].")`

**Move to Phase 6 when:** nuclei scan complete, kill_all_scans called, config findings logged.

---

## Phase 6: Synthesis & Report

**Tools:** `get_session_context`, `score_branches`, `distill_knowledge`, `generate_report`,
`log_reasoning`

**Goal:** Confirm coverage and generate the final report.

1. `get_session_context(session_id)` — full review: findings count, phases, branches explored
2. `score_branches(session_id)` — check all high-confidence (>0.6) branches have been explored.
   If any high-confidence branch was skipped, loop back and test it.
3. `distill_knowledge(session_id, "[3-5 key insights about this target's security posture]")`
4. `log_reasoning(session_id, "Orchestrator", "pre_report",
   '{"type":"decision","action":"generate_report","rationale":"all phases complete, [N] findings confirmed, no high-confidence branches remain"}')`
5. `generate_report(session_id)` — produces standalone HTML report
6. `log_reasoning(session_id, "Orchestrator", "engagement_complete",
   '{"type":"observation","report_path":"[path]","findings_count":[N],"severities":{"critical":[n],"high":[n],"medium":[n],"low":[n]}}')`

**Engagement is complete when:** generate_report returns a valid report_path.
Absence of findings IS a valid result — document it as clean.

---

## Tool Quick Reference — All 36

| # | Tool | Category | Purpose |
|---|------|----------|---------|
| 1 | `create_session` | Session | Start new engagement in SQLite + Neo4j |
| 2 | `set_branch` | Session | Declare active attack type in graph |
| 3 | `log_reasoning` | Session | Record thinking node to DAG |
| 4 | `add_injection_point` | Session | Register discovered input field |
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
| 23 | `test_auth_bypass` | Auth | Auth bypass on discovered endpoints |
| 24 | `test_idor` | Auth | IDOR on discovered ID endpoints |
| 25 | `test_csrf` | Auth | CSRF on discovered form endpoints |
| 26 | `analyse_cookies` | Auth | Cookie security flag auditor |
| 27 | `test_session_fixation` | Auth | Session fixation checker |
| 28 | `run_nuclei_scan` | Execution | Nuclei template scan (async) |
| 29 | `check_nuclei_status` | Execution | Poll nuclei scan job status |
| 30 | `kill_all_scans` | Execution | Stop all active async scans |
| 31 | `shell_exec` | Execution | Execute whitelisted shell commands |
| 32 | `generate_report` | Execution | Generate standalone HTML report |
| 33 | `select_skills` | Session | SkillDAG adaptive methodology selection |
| 34 | `declare_intent` | Session | Create authorisation contract for phase |
| 35 | `get_intent_incidents` | Session | Fetch MAST violation log for session |
| 36 | `read_skill` | Session | Load full methodology skill file |
