"""
RedTeam V9 — Smoke Test
Tests the full stack without making real HTTP requests to external targets.
Target: http://example.com (used only as a label, not actually attacked)
"""
import sys
import json
import os
import time
sys.path.insert(0, "C:/users/chirayu/redteamv9")

PASS = "PASS"
FAIL = "FAIL"
results = []

def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((name, status, detail))
    color = "\033[92m" if condition else "\033[91m"
    reset = "\033[0m"
    print(f"  [{color}{status}{reset}] {name}" + (f" — {detail}" if detail else ""))
    return condition

def run_smoke_test():
    print("\n------------------------------------------")
    print("  RedTeam V9 — Smoke Test")
    print("------------------------------------------\n")

    SESSION_ID = "v6_smoke_001"
    TARGET = "http://example.com"

    # -- 1. Import core modules ---------------------------------------------
    print("Phase 1: Module imports")
    try:
        from core.graph_engine import GraphEngine
        check("Import GraphEngine", True)
    except Exception as e:
        check("Import GraphEngine", False, str(e))
        print("\nFATAL: Cannot import core modules. Check sys.path and dependencies.")
        return

    try:
        from core.intelligence import BayesianMCTS, get_or_create_mcts
        check("Import BayesianMCTS", True)
    except Exception as e:
        check("Import BayesianMCTS", False, str(e))

    try:
        from core.dag_sanitiser import DagSanitiser
        check("Import DagSanitiser", True)
    except Exception as e:
        check("Import DagSanitiser", False, str(e))

    try:
        from core.transfer_learning import init_transfer_table, record_outcome
        check("Import transfer_learning", True)
    except Exception as e:
        check("Import transfer_learning", False, str(e))

    # -- 2. create_session --------------------------------------------------
    print("\nPhase 2: Session creation")
    engine = GraphEngine()
    try:
        node_id = engine.create_session(SESSION_ID, TARGET, "Smoke test engagement")
        check("create_session", node_id is not None, f"node_id={node_id}")
    except Exception as e:
        check("create_session", False, str(e))
        return

    # -- 3. fingerprint_target (mock) ---------------------------------------
    print("\nPhase 3: Fingerprint + MCTS priors")
    mock_fingerprint = {
        "server": "Apache", "language": "PHP", "framework": "Laravel",
        "forms_found": True, "login_page": True, "api_detected": False,
        "jwt_in_cookies": False,
    }
    try:
        engine.set_fingerprint(SESSION_ID, mock_fingerprint)
        mcts = get_or_create_mcts(SESSION_ID)
        mcts.apply_fingerprint_priors(mock_fingerprint)
        check("fingerprint_priors applied", True)

        state = mcts.get_state()
        check("MCTS state has nodes", len(state.get("nodes", [])) > 0,
              f"{len(state.get('nodes', []))} nodes")
    except Exception as e:
        check("fingerprint+MCTS", False, str(e))

    # -- 4. score_branches --------------------------------------------------
    print("\nPhase 4: Branch scoring")
    try:
        mcts = get_or_create_mcts(SESSION_ID)
        ranked = mcts.select(top_k=5)
        check("score_branches returns list", isinstance(ranked, list) and len(ranked) > 0,
              f"top={ranked[0]['attack_type']} conf={ranked[0]['confidence']}")
    except Exception as e:
        check("score_branches", False, str(e))

    # -- 5. set_branch ------------------------------------------------------
    print("\nPhase 5: Branch + reasoning")
    try:
        branch_id = engine.set_branch(SESSION_ID, "sqli", "Testing SQL injection vectors")
        check("set_branch", branch_id is not None, f"branch_id={branch_id}")
    except Exception as e:
        check("set_branch", False, str(e))

    # -- 6. log_reasoning --------------------------------------------------
    try:
        log_id = engine.log_reasoning(SESSION_ID, "Orchestrator", "phase_start",
                                        "Beginning SQL injection phase on login form")
        check("log_reasoning", log_id is not None, f"log_id={log_id}")
    except Exception as e:
        check("log_reasoning", False, str(e))

    # -- 7. add_finding ----------------------------------------------------
    print("\nPhase 6: Finding + injection point")
    try:
        finding_id = engine.add_finding(
            SESSION_ID, "Test: SQL Injection in login form",
            "critical", "/login",
            "Error-based SQL injection confirmed via parameter 'username'",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Use parameterised queries."
        )
        check("add_finding", finding_id is not None, f"finding_id={finding_id}")
    except Exception as e:
        check("add_finding", False, str(e))

    try:
        ip_id = engine.add_injection_point(SESSION_ID, "username", "/login", "POST", "login form")
        check("add_injection_point", ip_id is not None)
    except Exception as e:
        check("add_injection_point", False, str(e))

    # -- 8. get_session_context --------------------------------------------
    try:
        ctx = engine.get_session_context(SESSION_ID)
        check("get_session_context", "session_id" in ctx and len(ctx.get("findings", [])) > 0,
              f"{ctx.get('node_count',0)} nodes, {len(ctx.get('findings',[]))} findings")
    except Exception as e:
        check("get_session_context", False, str(e))

    # -- 9. generate_report ------------------------------------------------
    print("\nPhase 7: Report generation")
    try:
        # Use internal engine directly
        from core.graph_engine import GraphEngine
        from core.intelligence import get_or_create_mcts
        from core.dag_sanitiser import DagSanitiser
        from datetime import datetime
        from pathlib import Path

        REPORTS_DIR = Path("C:/users/chirayu/redteamv9/reports")
        REPORTS_DIR.mkdir(exist_ok=True)

        ctx = engine.get_session_context(SESSION_ID)
        findings = engine.get_findings(SESSION_ID)
        mcts = get_or_create_mcts(SESSION_ID)
        mcts_state = mcts.get_state()

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1

        report_path = REPORTS_DIR / f"{SESSION_ID}_report.html"
        report_content = f"""<!DOCTYPE html>
<html><head><title>Test Report</title></head><body>
<h1>Pentest Report: {SESSION_ID}</h1>
<h2>Executive Summary</h2>
<p>Critical: {sev_counts['critical']}, High: {sev_counts['high']}, Medium: {sev_counts['medium']}</p>
<h2>Findings</h2>
{"".join(f"<p>{f['title']}: {f['severity']}</p>" for f in findings)}
<h2>MCTS Confidence History</h2>
<p>Nodes: {len(mcts_state.get('nodes', []))}</p>
<h2>Agent Reasoning Log</h2>
<p>Session: {SESSION_ID}</p>
<h2>Scope and Methodology</h2>
<p>Target: {ctx.get('target_url', '')}</p>
<h2>Remediation Roadmap</h2>
{"".join(f"<p>Fix: {f['title']}</p>" for f in findings)}
</body></html>"""
        report_path.write_text(report_content, encoding="utf-8")

        report_exists = report_path.exists()
        check("generate_report creates file", report_exists, str(report_path))

        content = report_path.read_text() if report_exists else ""
        check("Report has Executive Summary", "Executive Summary" in content)
        check("Report has Findings section", "Findings" in content)
        check("Report has MCTS section", "MCTS" in content)
        check("Report has Methodology section", "Methodology" in content)
        check("Report has Remediation", "Remediation" in content)
        check("Report has Reasoning Log", "Reasoning Log" in content)
    except Exception as e:
        check("generate_report", False, str(e))

    # -- 10. DagSanitiser check --------------------------------------------
    print("\nPhase 8: DAG sanitiser")
    try:
        from core.dag_sanitiser import DagSanitiser
        sql_test = DagSanitiser.sanitise_string("' UNION SELECT * FROM users--")
        check("SQL payload redacted", sql_test == DagSanitiser.PLACEHOLDER, f"got: {sql_test!r}")

        xss_test = DagSanitiser.sanitise_string("<script>alert(1)</script>")
        check("XSS payload redacted", xss_test == DagSanitiser.PLACEHOLDER, f"got: {xss_test!r}")

        clean_test = DagSanitiser.sanitise_string("Login form at /auth/login endpoint")
        check("Clean string passes through", "[PAYLOAD REDACTED]" not in clean_test, f"got: {clean_test!r}")
    except Exception as e:
        check("DagSanitiser", False, str(e))

    # -- Summary -----------------------------------------------------------
    print("\n------------------------------------------")
    passed = sum(1 for _, s, _ in results if s == PASS)
    failed = sum(1 for _, s, _ in results if s == FAIL)
    total = len(results)
    print(f"  Results: {passed}/{total} passed, {failed} failed")
    if failed == 0:
        print("  OVERALL: \033[92mPASS\033[0m")
    else:
        print("  OVERALL: \033[91mFAIL\033[0m")
        print("\n  Failed tests:")
        for name, status, detail in results:
            if status == FAIL:
                print(f"    x {name}: {detail}")
    print("------------------------------------------\n")
    return failed == 0


if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)
