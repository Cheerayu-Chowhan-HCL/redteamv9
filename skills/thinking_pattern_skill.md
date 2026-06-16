---
name: Pentest Thinking Pattern
description: Mandatory reasoning and logging pattern for penetration test engagements. Always active during any pentest session. Ensures all decisions, hypotheses, observations and failures are logged via log_reasoning tool to the ThinkingDAG for live monitoring.
trigger: auto
---

# Thinking Pattern — RedTeam V9

You must narrate your thinking through every decision using log_reasoning. This is not
optional — it feeds the Thinking DAG, trains the BayesianMCTS, and makes your reasoning
auditable. A silent agent is a degraded agent.

**Critical rule:** Every hypothesis must be grounded in tool results, not prior knowledge.
You know nothing about the target until your tools tell you. Your reasoning must reflect this.

---

## Call Signature

```python
log_reasoning(
  session_id,    # str — your session ID
  agent,         # str — always "Orchestrator"
  step_label,    # str — "pre_test_sqli", "hypothesis_sqli", "failure_xss"
  content        # str — JSON object (see types below)
)
```

---

## Type: hypothesis — Before Testing

Use BEFORE launching any attack tool. Hypothesis must cite specific evidence from
a previous tool result — never prior knowledge about the target.

**WRONG (uses prior knowledge):**
```python
# BAD — do not write this
log_reasoning(session_id, "Orchestrator", "hypothesis_sqli",
  '{"type":"hypothesis","attack":"sqli","confidence":0.7,
    "rationale":"This type of app usually has SQLi"}')
```

**CORRECT (grounded in discovery):**
```python
log_reasoning(session_id, "Orchestrator", "hypothesis_sqli",
  '{"type":"hypothesis","attack":"sqli","confidence":0.6,
    "rationale":"crawl_links returned a POST form with text inputs at discovered endpoint. Java servlet detected from response headers. score_branches ranked sqli=0.82.",
    "expected":"error-based or boolean-blind injection on discovered POST parameters"}')

log_reasoning(session_id, "Orchestrator", "hypothesis_auth",
  '{"type":"hypothesis","attack":"auth_bypass","confidence":0.55,
    "rationale":"crawl_links found a form with credential-style fields (2 inputs, method=POST). fingerprint shows no WAF.",
    "expected":"SQL injection bypass or default credential match"}')

log_reasoning(session_id, "Orchestrator", "hypothesis_idor",
  '{"type":"hypothesis","attack":"idor","confidence":0.5,
    "rationale":"crawl_links returned endpoint with numeric ID in path pattern. Response body contains object data without apparent auth check.",
    "expected":"sequential ID enumeration will expose other object data"}')
```

---

## Type: observation — After Every Tool Call

Use after EVERY tool call. Lightweight — just summarise what the tool returned.
These are facts from this engagement, not assumed knowledge.

```python
log_reasoning(session_id, "Orchestrator", "post_fingerprint_target",
  '{"type":"observation","tool":"fingerprint_target",
    "finding":"Java servlet detected from X-Powered-By header. Framework: unclear. WAF: none detected.",
    "confidence":0.9}')

log_reasoning(session_id, "Orchestrator", "post_crawl_links",
  '{"type":"observation","tool":"crawl_links",
    "finding":"23 pages crawled. 4 forms discovered. 2 endpoints with numeric IDs. 1 POST form with credential-style inputs.",
    "confidence":1.0}')

log_reasoning(session_id, "Orchestrator", "post_score_branches",
  '{"type":"observation","tool":"score_branches",
    "finding":"rank1=sqli(0.82), rank2=auth_bypass(0.71), rank3=xss(0.55), rank4=idor(0.41), rank5=headers(0.30). Entropy=1.8.",
    "confidence":1.0}')

log_reasoning(session_id, "Orchestrator", "post_enumerate_endpoints",
  '{"type":"observation","tool":"enumerate_endpoints",
    "finding":"14 additional paths discovered beyond crawl. 3 returned 200, 11 returned 404/403.",
    "confidence":1.0}')
```

---

## Type: decision — Pursue or Abandon

Use when choosing to pursue OR abandon an attack branch. Decision must reference
score_branches output or a specific tool result — never intuition alone.

```python
# Pursuing — based on MCTS score + discovery evidence
log_reasoning(session_id, "Orchestrator", "decision_pursue_sqli",
  '{"type":"decision","chosen":"sqli","rejected":"xss",
    "reason":"MCTS score sqli=0.82 vs xss=0.31. POST form with text inputs discovered by crawl_links. Java backend from fingerprint.",
    "next_tool":"test_sqli"}')

# Abandoning — based on absence of discovery evidence
log_reasoning(session_id, "Orchestrator", "decision_abandon_xpath",
  '{"type":"decision","chosen":"skip_xpath","rejected":"xpath_injection",
    "reason":"No XML endpoints found by crawl or enumerate. Fingerprint shows no SOAP or XML processing. score_branches ranked xpath last=0.04.",
    "next_tool":"test_csrf"}')

# Phase skip — condition not met
log_reasoning(session_id, "Orchestrator", "decision_skip_auth",
  '{"type":"decision","chosen":"skip_phase_2","rejected":"auth_bypass",
    "reason":"crawl_links found 0 credential-style forms and 0 auth endpoints. No authentication surface discovered.",
    "next_tool":"test_sqli"}')

# Phase transition — based on completion evidence
log_reasoning(session_id, "Orchestrator", "decision_advance_phase3",
  '{"type":"decision","action":"advance","from_phase":"phase_2","to_phase":"phase_3",
    "rationale":"Auth bypass confirmed on discovered endpoint. 2 injection points registered. Advancing to injection testing.",
    "confidence":0.95}')
```

---

## Type: failure — Clean Result or Error

Use when a tool finds no vulnerability or returns an error. Failures train the MCTS —
always log them. A clean result is data, not wasted effort.

```python
# Clean result — no vulnerability (this IS a finding)
log_reasoning(session_id, "Orchestrator", "failure_xss_clean",
  '{"type":"failure","tool":"test_xss","attack":"xss","parameter":"discovered_param_name",
    "result":"no reflection found — output HTML-entity-encoded in response",
    "confidence":0.0,
    "note":"output encoding correct for this parameter — MCTS reward=0.0 recorded"}')

# Phase condition not met — no surface to test
log_reasoning(session_id, "Orchestrator", "failure_no_auth_surface",
  '{"type":"failure","tool":"test_auth_bypass","attack":"auth_bypass",
    "result":"skipped — crawl_links found no authentication forms or endpoints",
    "confidence":0.0,
    "note":"no auth surface discovered — this is a valid negative result"}')

# Tool error
log_reasoning(session_id, "Orchestrator", "failure_sqli_timeout",
  '{"type":"failure","tool":"test_sqli","attack":"sqli","parameter":"discovered_param",
    "result":"success:false — connection timeout after 30s",
    "confidence":0.0,
    "action":"calling kill_all_scans then retrying once"}')

# Branch exhausted — no further endpoints to test
log_reasoning(session_id, "Orchestrator", "failure_idor_no_ids",
  '{"type":"failure","tool":"test_idor","attack":"idor",
    "result":"skipped — crawl_links found 0 endpoints with numeric ID parameters",
    "confidence":0.0,
    "note":"no IDOR surface discovered — advancing to CSRF testing"}')
```

---

## Type: insight — Cross-Cutting Pattern

Use when you observe a pattern across multiple results that is worth preserving.

```python
log_reasoning(session_id, "Orchestrator", "insight_session_handling",
  '{"type":"insight",
    "content":"Session tokens observed in crawled responses do not appear to regenerate post-authentication — same token value seen before and after credential submission. Flagging for test_session_fixation.",
    "confidence":0.8}')

log_reasoning(session_id, "Orchestrator", "insight_no_waf",
  '{"type":"insight",
    "content":"fingerprint_target returned no WAF indicator. All injection tests returning raw error messages. Error-based injection likely feasible if SQLi exists.",
    "confidence":0.85}')
```

---

## Frequency Rules

| Situation | Log type | Mandatory? |
|-----------|----------|------------|
| Before any new attack type | `hypothesis` (grounded in tool data) | YES |
| After `score_branches` | `decision` (pursue/abandon each branch) | YES |
| After EVERY tool call | `observation` | YES |
| After confirmed vulnerability | `observation` + `add_finding` | YES |
| After clean / null result | `failure` | YES |
| When phase condition not met | `failure` (skip logged explicitly) | YES |
| After unexpected result | include in `observation` or `insight` | YES |
| Every 5 tool calls | `get_session_context` | YES |
| End of each phase | `distill_knowledge` + `score_branches` | YES |
| Phase transition | `decision` | YES |
| Before `generate_report` | `decision` | YES |

---

## Entropy Rule

After every `score_branches` call, check the entropy value in the result:

- **Entropy < 1.0** — the MCTS is confident. Commit deeply to the top-ranked branch
  before exploring others. Do not split attention.
- **Entropy 1.0–2.5** — moderate uncertainty. Test the top branch, then re-score.
- **Entropy > 2.5** — high uncertainty. The fingerprint may have been incomplete.
  Run `enumerate_endpoints` or `http_request` to gather more target data, then re-score.

---

## Why This Matters

- Each `log_reasoning` creates a **ThinkingNode** — visible as a purple node in the DAG UI
- The `confidence` field determines node colour intensity (high confidence = brighter)
- `failure` logs send reward=0.0 to BayesianMCTS — it learns from clean results too
- Hypothesis logs grounded in tool data create a verifiable audit trail
- Gaps in reasoning produce **orphaned attack nodes** — disconnected red nodes in the DAG
  with no thinking context, which weakens the final report and MCTS learning
