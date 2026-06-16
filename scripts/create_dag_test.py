"""Create v6_dag_test session with all node types for DAG visual verification."""
import sys
import json
sys.path.insert(0, "C:/users/chirayu/redteamv9")
from core.graph_engine import GraphEngine

ge = GraphEngine()
sid = "v6_dag_test"

ge.create_session(sid, "http://test.local", "DAG visual test")
ge.set_branch(sid, "recon",  "Recon phase — crawled 18 pages")
ge.set_branch(sid, "sqli",   "SQLi phase — POST form at /login")
ge.set_branch(sid, "xss",    "XSS phase — search param")

ge.add_injection_point(sid, "uid",    "/login",  "POST", "login form username field")
ge.add_injection_point(sid, "search", "/search", "GET",  "search box query param")

ge.add_finding(sid, "SQL Injection",  "critical", "/login",
    "SQLi bypass confirmed via uid param — login redirected to dashboard",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "Replace string concatenation with parameterised queries at /login handler.")
ge.add_finding(sid, "Reflected XSS", "high", "/search",
    "search param reflects input unencoded in response body — marker triggered",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "HTML-encode all output at /search. Implement Content-Security-Policy header.")
ge.add_finding(sid, "Missing HSTS",  "medium", "/",
    "Strict-Transport-Security header absent from all responses",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to all responses.")

ge.add_thinking_node(sid, "SQLi likely - POST form found at /login", 0.85, 0.4, 0.9,  "DECIDED")
ge.add_thinking_node(sid, "Auth bypass confirmed via SQLi bypass",   0.95, 0.2, 0.95, "EVALUATING")
ge.add_thinking_node(sid, "XSS in search param - reflected marker",  0.75, 0.5, 0.8,  "DECIDED")

ge.log_reasoning(sid, "Orchestrator", "hypothesis_sqli",
    json.dumps({"type":"hypothesis","attack":"sqli","confidence":0.85,
                "rationale":"crawl_links found POST form at /login with 2 text inputs",
                "expected":"error-based injection on uid parameter"}))
ge.log_reasoning(sid, "Orchestrator", "post_sqli",
    json.dumps({"type":"observation","tool":"test_sqli",
                "finding":"SQLi confirmed - bypass succeeded, redirect to /dashboard",
                "confidence":0.95}))
ge.log_reasoning(sid, "Orchestrator", "decision_pursue_xss",
    json.dumps({"type":"decision","chosen":"xss","rejected":"idor",
                "reason":"MCTS xss=0.71 vs idor=0.38. Search form found with GET param",
                "next_tool":"test_xss"}))
ge.log_reasoning(sid, "Orchestrator", "failure_idor_no_ids",
    json.dumps({"type":"failure","tool":"test_idor","attack":"idor",
                "result":"skipped - crawl found 0 numeric ID endpoints",
                "confidence":0.0,
                "note":"no IDOR surface discovered - valid negative result"}))

ge.distill_knowledge(sid, "SQLi on /login uid param - no WAF, error-based injection feasible")
ge.distill_knowledge(sid, "search param reflects input unencoded - XSS confirmed")
ge.distill_knowledge(sid, "PHASE_COMPLETE: Phase 3 - sqli+xss - 2 critical findings")

print("Test session created:", sid)
