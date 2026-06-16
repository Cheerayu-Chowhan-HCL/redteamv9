---
name: RedTeam V9 Thinking Pattern
description: Mandatory log_reasoning pattern guide for RedTeam V9 agents. Defines all 5 log types (hypothesis, decision, observation, surprise, failure) with examples and frequency rules.
---

# Thinking Pattern — RedTeam V9

You must narrate your thinking through every decision using log_reasoning. This is not
optional — it feeds the Thinking DAG, trains the BayesianMCTS, and makes your reasoning
auditable. A silent agent is a degraded agent.

---

## The Call Signature

```python
log_reasoning(
  session_id,    # str — your session ID
  agent,         # str — always "Orchestrator" unless you are a sub-agent
  step_label,    # str — short label: "pre_test_sqli", "hypothesis_auth", "failure_xss"
  content        # str — JSON object (see types below)
)
```

---

## Type: hypothesis

**Use when:** You have a belief about a vulnerability BEFORE testing it.
Fire this before launching any attack tool.

```python
log_reasoning(session_id, "Orchestrator", "hypothesis_sqli",
  '{"type":"hypothesis","attack":"sqli","confidence":0.75,
    "rationale":"PHP login form with GET parameter ?id= — high prior for SQLi. score_branches ranked sqli=0.82.",
    "expected":"error-based or boolean-blind injection on id parameter"}')

log_reasoning(session_id, "Orchestrator", "hypothesis_auth",
  '{"type":"hypothesis","attack":"auth_bypass","confidence":0.6,
    "rationale":"Default admin panel at /admin/login.asp, ASP.NET app. Will try SQLi bypass and default creds admin/admin.",
    "expected":"SQLi bypass likely given no WAF detected in fingerprint"}')

log_reasoning(session_id, "Orchestrator", "hypothesis_idor",
  '{"type":"hypothesis","attack":"idor","confidence":0.5,
    "rationale":"REST API endpoint /api/accounts/{id} discovered in crawl. No auth header visible in responses.",
    "expected":"sequential ID enumeration will return other users accounts"}')
```

---

## Type: decision

**Use when:** You choose to pursue OR abandon an attack branch.
Always log decisions with full rationale.

```python
# Pursuing a branch
log_reasoning(session_id, "Orchestrator", "decision_pursue_sqli",
  '{"type":"decision","action":"pursue","branch":"sqli","confidence":0.82,
    "rationale":"score_branches rank 1: sqli=0.82. PHP app, no WAF detected, 3 GET parameters in login form.",
    "next_tool":"test_sqli"}')

# Abandoning a branch
log_reasoning(session_id, "Orchestrator", "decision_abandon_xpath",
  '{"type":"decision","action":"abandon","branch":"xpath_injection","confidence":0.05,
    "rationale":"No XML endpoints found in crawl, fingerprint shows no XML processing, score_branches ranked xpath last at 0.04.",
    "next_tool":"test_xss"}')

# Phase transition
log_reasoning(session_id, "Orchestrator", "decision_advance_phase3",
  '{"type":"decision","action":"advance","from_phase":"phase_2","to_phase":"phase_3",
    "rationale":"Auth bypass confirmed (CVSS 9.8). Cookie flags missing. Moving to injection testing.",
    "confidence":0.95}')
```

---

## Type: observation

**Use after EVERY tool call.** This is the lightest-weight log — just what the tool returned.

```python
log_reasoning(session_id, "Orchestrator", "post_fingerprint_target",
  '{"type":"observation","tool":"fingerprint_target",
    "found":{"server":"Apache/2.4.41","language":"PHP/7.4","cms":"WordPress 5.8","waf":"none","cdn":"none"},
    "confidence":0.9}')

log_reasoning(session_id, "Orchestrator", "post_crawl_links",
  '{"type":"observation","tool":"crawl_links",
    "found":{"pages":23,"forms":4,"endpoints":["/login","/search","/contact","/upload"]},
    "confidence":1.0}')

log_reasoning(session_id, "Orchestrator", "post_check_headers",
  '{"type":"observation","tool":"check_headers",
    "found":{"missing":["Content-Security-Policy","X-Frame-Options","Strict-Transport-Security"],
             "present":["X-Content-Type-Options"]},
    "confidence":1.0}')

log_reasoning(session_id, "Orchestrator", "post_score_branches",
  '{"type":"observation","tool":"score_branches",
    "found":{"rank1":"sqli=0.82","rank2":"auth_bypass=0.71","rank3":"xss=0.55","rank4":"idor=0.41"},
    "confidence":1.0}')
```

---

## Type: surprise

**Use when:** A tool result is unexpected — better or worse than your hypothesis predicted.

```python
# Unexpected success (more vulnerable than expected)
log_reasoning(session_id, "Orchestrator", "surprise_easy_bypass",
  '{"type":"surprise","attack":"auth_bypass",
    "found":"admin login bypassed with username: admin\' -- and blank password",
    "expected":"would need full multi-step SQLi payload",
    "impact":"critical","cvss_estimate":9.8,
    "note":"WAF absent, no input sanitisation at all — trivial bypass"}')

# Unexpected failure (more secure than expected)
log_reasoning(session_id, "Orchestrator", "surprise_sqli_blocked",
  '{"type":"surprise","attack":"sqli",
    "found":"all payloads returned 403 — WAF blocking SQL keywords",
    "expected":"error-based injection based on PHP + no WAF flag from fingerprint",
    "actual_confidence":0.1,
    "note":"WAF not detected by fingerprint_target — trying WAF bypass payloads via retrieve_knowledge"}')

# Unexpected off-branch finding
log_reasoning(session_id, "Orchestrator", "surprise_exposed_panel",
  '{"type":"surprise","attack":"recon",
    "found":"nuclei discovered /phpmyadmin exposed with no auth required",
    "expected":"no exposed admin panels",
    "impact":"critical",
    "note":"logging as Critical finding now, continuing engagement"}')
```

---

## Type: failure

**Use when:** A tool finds no vulnerability or returns an error.
Failures train the MCTS — always log them.

```python
# Clean result — no vulnerability
log_reasoning(session_id, "Orchestrator", "failure_xss_clean",
  '{"type":"failure","tool":"test_xss","attack":"xss","parameter":"search",
    "result":"no reflection found — all output HTML-entity-encoded",
    "confidence":0.0,
    "note":"output encoding is correct for this parameter — closing XSS for this field"}')

# Tool error
log_reasoning(session_id, "Orchestrator", "failure_sqli_timeout",
  '{"type":"failure","tool":"test_sqli","attack":"sqli","parameter":"id",
    "result":"success:false — connection timeout after 30s",
    "confidence":0.0,
    "action":"will retry once after kill_all_scans"}')

# Branch exhausted
log_reasoning(session_id, "Orchestrator", "failure_csrf_secure",
  '{"type":"failure","tool":"test_csrf","attack":"csrf",
    "result":"valid CSRF token present on all forms, per-request uniqueness confirmed, entropy >128 bits",
    "confidence":0.0,
    "note":"CSRF well-implemented — closing branch, advancing to config_review"}')
```

---

## Frequency Rules

| Situation | Log type | Mandatory? |
|-----------|----------|------------|
| Before any new attack type | `hypothesis` | YES |
| After `score_branches` | `decision` (pursue/abandon) | YES |
| After EVERY tool call | `observation` | YES |
| After confirmed vulnerability | `observation` + `add_finding` | YES |
| After clean / null result | `failure` | YES |
| After unexpected result (either direction) | `surprise` | YES |
| Every 5 tool calls | `get_session_context` | YES |
| End of each phase | `distill_knowledge` | YES |
| Phase transition | `decision` | YES |
| Before `generate_report` | `decision` | YES |

---

## Why This Matters

- Each `log_reasoning` call creates a **ThinkingNode** visible as a purple node in the
  DAG UI left panel
- The `confidence` field in your logs determines **node colour intensity** in the UI
  (high confidence = brighter purple)
- `failure` logs send reward=0.0 to the BayesianMCTS — it learns what NOT to try on
  similar targets next time
- `surprise` logs trigger **UCB1 exploration bonus** — the MCTS will re-score this branch
  upward in future sessions against similar tech stacks
- All logs are sanitised before display — raw payloads are stripped from the DAG UI but
  preserved in raw form in SQLite for your reference during the engagement
- Gaps in reasoning (silent tool calls) produce **orphaned attack nodes** — the DAG shows
  disconnected red nodes with no thinking context, weakening the final report
